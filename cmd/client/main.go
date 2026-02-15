package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ssrok/internal/constants"
	"ssrok/internal/protocol"
	"ssrok/internal/tunnel"
	"ssrok/internal/utils"
)

const (
	colorReset  = constants.ColorReset
	colorBold   = constants.ColorBold
	colorDim    = constants.ColorDim
	colorCyan   = constants.ColorCyan
	colorGreen  = constants.ColorGreen
	colorYellow = constants.ColorYellow
	colorRed    = constants.ColorRed
	colorPurple = constants.ColorPurple
)

func printBanner() {
	fmt.Println()
	fmt.Println(colorCyan + "╔══════════════════════════════════════════════════════════╗" + colorReset)
	fmt.Println(colorCyan + "║" + colorBold + "                      🔒 ssrok v1.0                       " + colorReset + colorCyan + "║" + colorReset)
	fmt.Println(colorCyan + "║" + colorDim + "           Secure Ephemeral Reverse Proxy                 " + colorReset + colorCyan + "║" + colorReset)
	fmt.Println(colorCyan + "╚══════════════════════════════════════════════════════════╝" + colorReset)
	fmt.Println()
}

func printHint(text string) {
	fmt.Println(colorDim + "   💡 " + text + colorReset)
}

func printStep(number int, text string) {
	fmt.Printf(colorBold+colorCyan+"%d."+colorReset+" %s\n", number, text)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println(constants.MsgUsage)
		fmt.Println(constants.MsgExample)
		os.Exit(1)
	}

	port, err := strconv.Atoi(os.Args[1])
	if err != nil || port < constants.MinPort || port > constants.MaxPort {
		fmt.Printf(colorRed+"Error: Invalid port number: %s"+colorReset+"\n", os.Args[1])
		os.Exit(1)
	}

	serverURL := utils.GetEnv("SSROK_SERVER", constants.DefaultServerURL)

	// Auto-detect HTTPS and skip TLS verify for localhost
	useHTTPS := strings.HasPrefix(serverURL, "https://")
	skipTLSVerify := useHTTPS && (strings.Contains(serverURL, "localhost") || strings.Contains(serverURL, "127.0.0.1"))

	printBanner()

	reader := bufio.NewReader(os.Stdin)

	printStep(1, "Local server configuration")
	printHint("Does your local server (localhost:" + strconv.Itoa(port) + ") require HTTPS?")
	printHint("Note: This is for the connection between ssrok and your local app.")
	printHint("The public tunnel URL will handle HTTPS automatically.")
	fmt.Printf(colorBold + "   Use HTTPS for local connection? [y/N]: " + colorReset)
	useTLSStr, _ := reader.ReadString('\n')
	useTLSStr = strings.TrimSpace(useTLSStr)
	useTLS := strings.ToLower(useTLSStr) == "y"
	if useTLS {
		printHint(colorGreen + "Enabled: ssrok will connect to localhost using HTTPS" + colorReset)
	} else {
		printHint(colorDim + "Disabled: ssrok will connect to localhost using HTTP" + colorReset)
	}
	fmt.Println()

	printStep(2, "Secure your tunnel (optional)")
	printHint("Leave empty for token-only access, set password for extra protection")
	fmt.Print(colorBold + "   Password: " + colorReset)
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	if password != "" && len(password) < 4 {
		printHint(colorYellow + "   ⚠ Warning: Minimum 4 characters recommended" + colorReset)
	}
	fmt.Println()

	printStep(3, "Set rate limiting (0 = unlimited)")
	printHint("Requests per minute per IP address. 0 disables rate limiting.")
	fmt.Printf(colorBold+"   Requests per minute [%d]: "+colorReset, constants.DefaultRateLimit)
	rateLimitStr, _ := reader.ReadString('\n')
	rateLimitStr = strings.TrimSpace(rateLimitStr)

	rateLimit := constants.DefaultRateLimit
	if rateLimitStr != "" {
		rl, err := strconv.Atoi(rateLimitStr)
		if err == nil && rl >= 0 {
			rateLimit = rl
			if rateLimit == 0 {
				printHint(colorYellow + "Rate limiting disabled - unlimited requests allowed" + colorReset)
			} else {
				printHint(fmt.Sprintf("Rate limit set to %d requests per minute per IP", rateLimit))
			}
		} else {
			printHint(fmt.Sprintf("Invalid input, using default: %d requests per minute", constants.DefaultRateLimit))
		}
	} else {
		printHint(fmt.Sprintf("Using default: %d requests per minute per IP", constants.DefaultRateLimit))
	}
	fmt.Println()

	printStep(4, "Connecting to server...")
	fmt.Println(colorDim + "   Initializing secure tunnel..." + colorReset)

	config := protocol.ConfigRequest{
		Port:      port,
		Password:  password,
		RateLimit: rateLimit,
		UseTLS:    useTLS,
	}

	resp, err := registerTunnel(serverURL, config, skipTLSVerify)
	if err != nil {
		// If using HTTP and failed with 400 (Client sent HTTP query to HTTPS server), try HTTPS
		if strings.HasPrefix(serverURL, "http://") && strings.Contains(err.Error(), "status 400") {
			printHint(colorYellow + "HTTP connection failed, attempting HTTPS..." + colorReset)
			serverURL = strings.Replace(serverURL, "http://", "https://", 1)

			// Recalculate skipTLSVerify for the new URL
			skipTLSVerify = strings.Contains(serverURL, "localhost") || strings.Contains(serverURL, "127.0.0.1")

			resp, err = registerTunnel(serverURL, config, skipTLSVerify)
		}
	}

	if err != nil {
		fmt.Println()
		fmt.Println(colorRed + "   ✗ Failed to connect: " + err.Error() + colorReset)
		fmt.Println()
		os.Exit(1)
	}

	fmt.Println(colorGreen + "   ✓ Tunnel registered successfully!" + colorReset)

	magicURL := fmt.Sprintf("%s?token=%s", resp.URL, resp.Token)
	localProto := "http"
	if useTLS {
		localProto = "https"
	}
	localAddr := fmt.Sprintf("%s://localhost:%d", localProto, port)
	expiresAt := time.Now().Add(resp.ExpiresIn).Format(constants.TimeFormatShort)

	// Calculate box width based on longest URL
	maxLen := len(magicURL)
	if len(resp.URL) > maxLen {
		maxLen = len(resp.URL)
	}
	if len(localAddr) > maxLen {
		maxLen = len(localAddr)
	}
	boxWidth := maxLen + 24
	if boxWidth < 60 {
		boxWidth = 60
	}

	pad := func(s string, width int) string {
		if len(s) >= width {
			return s
		}
		return s + strings.Repeat(" ", width-len(s))
	}

	hLine := strings.Repeat("─", boxWidth-2)
	hLineThin := strings.Repeat("─", boxWidth-2)
	emptyInner := strings.Repeat(" ", boxWidth-2)

	fmt.Println()
	fmt.Println()

	// Top border
	fmt.Printf("   %s╭%s╮%s\n", colorGreen, hLine, colorReset)
	// Title
	title := "🚀 Tunnel Active"
	titlePad := (boxWidth - 2 - len(title) - 2) / 2 // -2 for emoji width
	if titlePad < 0 {
		titlePad = 0
	}
	titleLine := strings.Repeat(" ", titlePad) + title + strings.Repeat(" ", boxWidth-2-titlePad-len(title)-2)
	fmt.Printf("   %s│%s%s%s%s│%s\n", colorGreen, colorReset, colorBold, titleLine, colorGreen, colorReset)
	// Separator
	fmt.Printf("   %s├%s┤%s\n", colorGreen, hLineThin, colorReset)
	// Empty line
	fmt.Printf("   %s│%s%s%s│%s\n", colorGreen, colorReset, emptyInner, colorGreen, colorReset)

	// Magic URL
	magicLabel := " ✨ Magic URL  "
	magicValue := pad(magicURL, boxWidth-2-len(magicLabel)-1) + " "
	fmt.Printf("   %s│%s%s%s%s%s%s│%s\n", colorGreen, colorReset, colorBold+colorPurple, magicLabel, colorCyan, magicValue, colorGreen, colorReset)

	// Empty line
	fmt.Printf("   %s│%s%s%s│%s\n", colorGreen, colorReset, emptyInner, colorGreen, colorReset)

	// Raw URL
	rawLabel := " 🔗 Raw URL    "
	rawValue := pad(resp.URL, boxWidth-2-len(rawLabel)-1) + " "
	fmt.Printf("   %s│%s%s%s%s%s%s│%s\n", colorGreen, colorReset, colorBold, rawLabel, colorYellow, rawValue, colorGreen, colorReset)

	// Empty line
	fmt.Printf("   %s│%s%s%s│%s\n", colorGreen, colorReset, emptyInner, colorGreen, colorReset)

	// Thin separator
	fmt.Printf("   %s├%s┤%s\n", colorGreen, hLineThin, colorReset)

	// Local & Expires
	localLabel := " 🖥  Local      "
	localValue := pad(localAddr, boxWidth-2-len(localLabel)-1) + " "
	fmt.Printf("   %s│%s%s%s%s%s%s│%s\n", colorGreen, colorReset, colorDim, localLabel, colorReset, localValue, colorGreen, colorReset)

	expiresLabel := " ⏱  Expires    "
	expiresStr := fmt.Sprintf("%s (%s)", expiresAt, constants.DurationHour)
	expiresValue := pad(expiresStr, boxWidth-2-len(expiresLabel)-1) + " "
	fmt.Printf("   %s│%s%s%s%s%s%s│%s\n", colorGreen, colorReset, colorDim, expiresLabel, colorReset, expiresValue, colorGreen, colorReset)

	// Empty line
	fmt.Printf("   %s│%s%s%s│%s\n", colorGreen, colorReset, emptyInner, colorGreen, colorReset)

	// Thin separator
	fmt.Printf("   %s├%s┤%s\n", colorGreen, hLineThin, colorReset)

	// Hints
	hint1 := pad(" 📋 Share Magic URL → direct access (no password)", boxWidth-2)
	hint2 := pad(" 🔒 Share Raw URL   → requires password", boxWidth-2)
	fmt.Printf("   %s│%s%s%s%s│%s\n", colorGreen, colorReset, colorDim, hint1, colorGreen, colorReset)
	fmt.Printf("   %s│%s%s%s%s│%s\n", colorGreen, colorReset, colorDim, hint2, colorGreen, colorReset)

	// Empty line
	fmt.Printf("   %s│%s%s%s│%s\n", colorGreen, colorReset, emptyInner, colorGreen, colorReset)

	// Ctrl+C
	ctrlc := " Press Ctrl+C to stop"
	ctrlcPad := (boxWidth - 2 - len(ctrlc)) / 2
	ctrlcLine := strings.Repeat(" ", ctrlcPad) + ctrlc + strings.Repeat(" ", boxWidth-2-ctrlcPad-len(ctrlc))
	fmt.Printf("   %s│%s%s%s%s│%s\n", colorGreen, colorReset, colorBold, ctrlcLine, colorGreen, colorReset)

	// Bottom border
	fmt.Printf("   %s╰%s╯%s\n", colorGreen, hLine, colorReset)
	fmt.Println()

	wsURL := resp.URL
	// Detect protocol from server response URL, not from serverURL env var
	if strings.HasPrefix(wsURL, "https://") || strings.HasPrefix(wsURL, "wss://") {
		// Server is HTTPS, ensure WebSocket is wss://
		if strings.HasPrefix(wsURL, "http://") {
			wsURL = strings.Replace(wsURL, "http://", "wss://", 1)
		} else if !strings.HasPrefix(wsURL, "wss://") {
			wsURL = "wss://" + strings.TrimPrefix(wsURL, "https://")
		}
	} else {
		// Server is HTTP, ensure WebSocket is ws://
		if strings.HasPrefix(wsURL, "https://") {
			wsURL = strings.Replace(wsURL, "https://", "ws://", 1)
		} else if !strings.HasPrefix(wsURL, "ws://") {
			wsURL = "ws://" + strings.TrimPrefix(wsURL, "http://")
		}
	}
	tunnelUUID := resp.UUID
	if tunnelUUID == "" {
		tunnelUUID = extractUUID(resp.URL)
	}
	wsURL = strings.Replace(wsURL, "/"+tunnelUUID, "/ws/"+tunnelUUID, 1)

	// Append token to WebSocket URL
	if strings.Contains(wsURL, "?") {
		wsURL = wsURL + "&token=" + resp.Token
	} else {
		wsURL = wsURL + "?token=" + resp.Token
	}

	fmt.Println(colorDim + "   Establishing WebSocket connection..." + colorReset)
	t, err := tunnel.ConnectClient(wsURL, port, tunnelUUID, skipTLSVerify, useTLS)
	if err != nil {
		fmt.Println()
		fmt.Println(colorRed + "   ✗ Tunnel connection failed: " + err.Error() + colorReset)
		fmt.Println()
		os.Exit(1)
	}
	fmt.Println(colorGreen + "   ✓ WebSocket tunnel active" + colorReset)
	fmt.Println()

	// Start processing streams from the server
	go func() {
		if err := t.Process(); err != nil {
			fmt.Printf("\n%s   ✗ Connection lost: %v%s\n", colorRed, err, colorReset)
			os.Exit(1)
		}
	}()

	// Display log file path
	fmt.Println(colorDim + "   📝 Logs: " + t.GetLogPath() + colorReset)
	fmt.Println()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan

	fmt.Println()
	fmt.Println(colorYellow + "   🛑 Shutting down tunnel..." + colorReset)
	t.Close()
	fmt.Println(colorGreen + "   ✓ Tunnel closed. Goodbye!" + colorReset)
	fmt.Println()
}

func registerTunnel(serverURL string, config protocol.ConfigRequest, skipTLSVerify bool) (*protocol.ConfigResponse, error) {
	jsonData, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	if skipTLSVerify {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	resp, err := client.Post(
		serverURL+constants.EndpointRegister,
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(bytes.TrimSpace(body)))
	}

	var result protocol.ConfigResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func extractUUID(tunnelURL string) string {
	u, err := url.Parse(tunnelURL)
	if err != nil {
		return ""
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}
