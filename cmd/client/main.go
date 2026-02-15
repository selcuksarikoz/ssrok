package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
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

	printBanner()

	reader := bufio.NewReader(os.Stdin)

	printStep(1, "Secure your tunnel (optional)")
	printHint("Leave empty for no password protection - anyone with the URL can access")
	printHint("Set a password to require authentication via login page")
	fmt.Print(colorBold + "   Password: " + colorReset)
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	if password != "" && len(password) < 4 {
		fmt.Println()
		fmt.Println(colorYellow + "   ⚠ Warning: Password is very short (minimum 4 characters recommended)" + colorReset)
		fmt.Println()
	}

	if password == "" {
		printHint(colorYellow + "⚠ No password set - tunnel is publicly accessible" + colorReset)
	} else {
		printHint("Password protection enabled - visitors must authenticate")
	}
	fmt.Println()

	printStep(2, "Set rate limiting (0 = unlimited)")
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

	printStep(3, "Connecting to server...")
	fmt.Println(colorDim + "   Initializing secure tunnel..." + colorReset)

	config := protocol.ConfigRequest{
		Port:      port,
		Password:  password,
		RateLimit: rateLimit,
	}

	resp, err := registerTunnel(serverURL, config)
	if err != nil {
		fmt.Println()
		fmt.Println(colorRed + "   ✗ Failed to connect: " + err.Error() + colorReset)
		fmt.Println()
		os.Exit(1)
	}

	fmt.Println(colorGreen + "   ✓ Tunnel registered successfully!" + colorReset)

	magicURL := fmt.Sprintf("%s?token=%s", resp.URL, resp.Token)

	fmt.Println()
	fmt.Println(colorGreen + "╔══════════════════════════════════════════════════════════╗" + colorReset)
	fmt.Println(colorGreen + "║" + colorBold + "                    🚀 Tunnel Active                      " + colorReset + colorGreen + "║" + colorReset)
	fmt.Println(colorGreen + "╠══════════════════════════════════════════════════════════╣" + colorReset)
	fmt.Printf(colorGreen+"║"+colorReset+"  "+colorBold+"Magic URL:"+colorReset+" "+colorCyan+"%-45s"+colorGreen+"║\n"+colorReset, magicURL)
	fmt.Println(colorGreen + "╠══════════════════════════════════════════════════════════╣" + colorReset)
	fmt.Printf(colorGreen+"║"+colorReset+"  "+colorBold+"Raw URL:"+colorReset+"   "+colorYellow+"%-45s"+colorGreen+"║\n"+colorReset, resp.URL)
	fmt.Println(colorGreen + "╠══════════════════════════════════════════════════════════╣" + colorReset)
	fmt.Printf(colorGreen+"║"+colorReset+"  "+colorBold+"Local:"+colorReset+"     http://localhost:%-28d"+colorGreen+"║\n"+colorReset, port)
	fmt.Println(colorGreen + "╠══════════════════════════════════════════════════════════╣" + colorReset)
	fmt.Printf(colorGreen+"║"+colorReset+"  "+colorBold+"Expires:"+colorReset+"   %-45s"+colorGreen+"║\n"+colorReset, time.Now().Add(resp.ExpiresIn).Format(constants.TimeFormatShort)+" ("+constants.DurationHour+")")
	fmt.Println(colorGreen + "╚══════════════════════════════════════════════════════════╝" + colorReset)
	fmt.Println()
	fmt.Println(colorDim + "   📋 Share the Magic URL for direct access (no password required)" + colorReset)
	fmt.Println(colorDim + "   🔒 Share the Raw URL + password for authenticated access" + colorReset)
	fmt.Println()
	fmt.Println(colorBold + "   Press Ctrl+C to stop" + colorReset)
	fmt.Println()

	wsURL := resp.URL
	// WebSocket protocol should match server's protocol
	// wss:// for HTTPS, ws:// for HTTP
	if strings.HasPrefix(wsURL, "https://") {
		wsURL = "wss://" + strings.TrimPrefix(wsURL, "https://")
	} else {
		// Default to ws:// for http or unknown protocols
		wsURL = "ws://" + strings.TrimPrefix(wsURL, "http://")
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
	t, err := tunnel.ConnectClient(wsURL, port, tunnelUUID)
	if err != nil {
		fmt.Println()
		fmt.Println(colorRed + "   ✗ Tunnel connection failed: " + err.Error() + colorReset)
		fmt.Println()
		os.Exit(1)
	}
	fmt.Println(colorGreen + "   ✓ WebSocket tunnel active" + colorReset)
	fmt.Println()

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

func registerTunnel(serverURL string, config protocol.ConfigRequest) (*protocol.ConfigResponse, error) {
	jsonData, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(
		serverURL+constants.EndpointRegister,
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
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
