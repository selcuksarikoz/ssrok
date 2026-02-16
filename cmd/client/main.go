package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ssrok/internal/constants"
	"ssrok/internal/dashboard"
	"ssrok/internal/tunnel"
	"ssrok/internal/types"
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
	fmt.Printf("  %s%sssrok%s %sv%s%s\n", constants.ColorBold, constants.ColorCyan, constants.ColorReset, constants.ColorBold, constants.Version, constants.ColorReset)
	fmt.Printf("  %sSecure Ephemeral Reverse Proxy%s\n", constants.ColorDim, constants.ColorReset)
	fmt.Println()
}

func printHint(text string) {
	fmt.Printf("  %s%s%s\n", colorDim, text, colorReset)
}

func printStep(number int, text string) {
	fmt.Printf("  %s%s▸%s %s\n", colorBold, colorCyan, colorReset, text)
}

func printField(label, value, valueColor string) {
	fmt.Printf("  %s%-12s%s %s%s%s\n", colorDim, label, colorReset, valueColor, value, colorReset)
}

func printSep() {
	fmt.Printf("  %s%s%s\n", colorDim, strings.Repeat("─", 50), colorReset)
}

func main() {
	flag.Usage = func() {
		fmt.Println()
		fmt.Printf("  %s%sssrok%s %sv%s%s\n", constants.ColorBold, constants.ColorCyan, constants.ColorReset, constants.ColorBold, constants.Version, constants.ColorReset)
		fmt.Println()
		fmt.Printf("  %sUsage:%s\n", constants.ColorBold, constants.ColorReset)
		fmt.Printf("    ssrok %s<port>%s              # e.g. ssrok 3000\n", constants.ColorCyan, constants.ColorReset)
		fmt.Printf("    ssrok %s<ip>:<port>%s         # e.g. ssrok 192.168.1.100:8080\n", constants.ColorCyan, constants.ColorReset)
		fmt.Println()
		fmt.Printf("  %sFlags:%s\n", constants.ColorBold, constants.ColorReset)
		flag.VisitAll(func(f *flag.Flag) {
			fmt.Printf("    -%-12s %s\n", f.Name, f.Usage)
		})
		fmt.Println()
	}

	versionFlag := flag.Bool("version", false, "show version")
	updateFlag := flag.Bool("update", false, "update ssrok via brew")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("  %s%sssrok%s %sv%s%s\n", constants.ColorBold, constants.ColorCyan, constants.ColorReset, constants.ColorBold, constants.Version, constants.ColorReset)
		fmt.Printf("  %sSecure Ephemeral Reverse Proxy%s\n", constants.ColorDim, constants.ColorReset)
		os.Exit(0)
	}

	if *updateFlag {
		fmt.Println("  Checking for updates via Homebrew...")

		checkCmd := exec.Command("brew", "--version")
		if err := checkCmd.Run(); err != nil {
			fmt.Printf("  %s⚠ Homebrew not found. Please install Homebrew first:%s\n", constants.ColorYellow, constants.ColorReset)
			fmt.Println("  https://brew.sh")
			os.Exit(1)
		}

		fmt.Println("  Running: brew update && brew upgrade ssrok")
		fmt.Println()

		cmd := exec.Command("brew", "update")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Run()

		cmd = exec.Command("brew", "upgrade", "ssrok")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("  %s⚠ Upgrade failed or ssrok not installed%s\n", constants.ColorYellow, constants.ColorReset)
			fmt.Println("  Try: brew install ssrok")
			os.Exit(1)
		}

		fmt.Println()
		fmt.Printf("  %s✓ Update complete!%s\n", constants.ColorGreen, constants.ColorReset)
		os.Exit(0)
	}

	if len(os.Args) < 2 {
		fmt.Println(constants.MsgUsage)
		fmt.Println(constants.MsgExample)
		os.Exit(1)
	}

	arg := os.Args[1]
	var targetHost string
	var targetPort int

	// Try to parse as port number only first
	if p, err := strconv.Atoi(arg); err == nil {
		targetHost = "localhost"
		targetPort = p
	} else {
		// Try to parse as host:port
		host, portStr, err := net.SplitHostPort(arg)
		if err != nil {
			fmt.Printf(colorRed+"Error: Invalid argument: %s\nMust be a port number (e.g. 3000) or address:port (e.g. localhost:3000)"+colorReset+"\n", arg)
			os.Exit(1)
		}
		if host == "" {
			targetHost = "localhost"
		} else {
			targetHost = host
		}
		p, err := strconv.Atoi(portStr)
		if err != nil {
			fmt.Printf(colorRed+"Error: Invalid port number: %s"+colorReset+"\n", portStr)
			os.Exit(1)
		}
		targetPort = p
	}

	if targetPort < constants.MinPort || targetPort > constants.MaxPort {
		fmt.Printf(colorRed+"Error: Port number out of range: %d"+colorReset+"\n", targetPort)
		os.Exit(1)
	}
	port := targetPort // alias for compatibility

	serverURL := utils.GetEnv("SSROK_SERVER", constants.DefaultServerURL)
	serverURL = strings.TrimSuffix(serverURL, "/")

	// Auto-detect HTTPS and skip TLS verify for localhost
	useHTTPS := strings.HasPrefix(serverURL, "https://")
	skipTLSVerify := useHTTPS && (strings.Contains(serverURL, "localhost") ||
		strings.Contains(serverURL, "127.0.0.1") ||
		strings.Contains(serverURL, ".onrender.com") ||
		strings.Contains(serverURL, ".railway.app") ||
		strings.Contains(serverURL, ".fly.io"))

	printBanner()

	reader := bufio.NewReader(os.Stdin)

	printStep(1, "Local server configuration")
	printHint("Target: " + targetHost + ":" + strconv.Itoa(port))
	printHint("HTTPS required for local connection?")
	fmt.Printf("  %sHTTPS? [y/N]:%s ", colorBold, colorReset)
	useTLSStr, _ := reader.ReadString('\n')
	useTLSStr = strings.TrimSpace(useTLSStr)
	useTLS := strings.ToLower(useTLSStr) == "y"
	if useTLS {
		printHint(colorGreen + "→ HTTPS enabled" + colorReset)
	} else {
		printHint("→ HTTP")
	}
	fmt.Println()

	printStep(2, "Password (optional)")
	printHint("Leave empty for 'No Password' login access")
	fmt.Printf("  %sPassword:%s ", colorBold, colorReset)
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	if password != "" && len(password) < 4 {
		fmt.Printf("  %s⚠ min 4 chars recommended%s\n", colorYellow, colorReset)
	}
	fmt.Println()

	printStep(3, "Rate limit (0 = unlimited)")
	fmt.Printf("  %sReq/min [%d]:%s ", colorBold, constants.DefaultRateLimit, colorReset)
	rateLimitStr, _ := reader.ReadString('\n')
	rateLimitStr = strings.TrimSpace(rateLimitStr)

	rateLimit := constants.DefaultRateLimit
	if rateLimitStr != "" {
		rl, err := strconv.Atoi(rateLimitStr)
		if err == nil && rl >= 0 {
			rateLimit = rl
			if rateLimit == 0 {
				printHint(colorYellow + "→ unlimited" + colorReset)
			} else {
				printHint(fmt.Sprintf("→ %d req/min per IP", rateLimit))
			}
		} else {
			printHint(fmt.Sprintf("→ default: %d req/min", constants.DefaultRateLimit))
		}
	}
	fmt.Println()

	printStep(4, "Duration (5-1440 min)")
	fmt.Printf("  %sMinutes [60]:%s ", colorBold, colorReset)
	durationStr, _ := reader.ReadString('\n')
	durationStr = strings.TrimSpace(durationStr)

	expiresIn := constants.SessionDuration
	if durationStr != "" {
		mins, err := strconv.Atoi(durationStr)
		if err == nil && mins > 0 {
			expiresIn = time.Duration(mins) * time.Minute
			if expiresIn < constants.MinSessionDuration {
				expiresIn = constants.MinSessionDuration
				printHint(fmt.Sprintf("%s→ clamped to %s%s", colorYellow, expiresIn, colorReset))
			} else if expiresIn > constants.MaxSessionDuration {
				expiresIn = constants.MaxSessionDuration
				printHint(fmt.Sprintf("%s→ clamped to %s%s", colorYellow, expiresIn, colorReset))
			} else {
				printHint(fmt.Sprintf("→ %d min", mins))
			}
		} else {
			printHint(fmt.Sprintf("%s→ default: 60 min%s", colorYellow, colorReset))
		}
	}
	fmt.Println()

	printSep()
	fmt.Printf("  %sConnecting...%s\n", colorDim, colorReset)

	config := types.ConfigRequest{
		Port:      port,
		Password:  password,
		RateLimit: rateLimit,
		UseTLS:    useTLS,
		ExpiresIn: expiresIn,
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

	magicURL := fmt.Sprintf("%s?token=%s", resp.URL, resp.Token)
	localProto := "http"
	if useTLS {
		localProto = "https"
	}
	localAddr := fmt.Sprintf("%s://%s:%d", localProto, targetHost, port)
	expiresAt := time.Now().Add(resp.ExpiresIn).Format(constants.TimeFormatShort)
	durationDisplay := utils.FormatDuration(resp.ExpiresIn)

	wsURL := resp.URL
	if strings.HasPrefix(wsURL, "https://") || strings.HasPrefix(wsURL, "wss://") {
		if strings.HasPrefix(wsURL, "http://") {
			wsURL = strings.Replace(wsURL, "http://", "wss://", 1)
		} else if !strings.HasPrefix(wsURL, "wss://") {
			wsURL = "wss://" + strings.TrimPrefix(wsURL, "https://")
		}
	} else {
		if strings.HasPrefix(wsURL, "https://") {
			wsURL = strings.Replace(wsURL, "https://", "ws://", 1)
		} else if !strings.HasPrefix(wsURL, "ws://") {
			wsURL = "ws://" + strings.TrimPrefix(wsURL, "http://")
		}
	}
	tunnelUUID := resp.UUID
	if tunnelUUID == "" {
		tunnelUUID = utils.ExtractUUID(resp.URL)
	}
	wsURL = strings.Replace(wsURL, "/"+tunnelUUID, "/ws/"+tunnelUUID, 1)
	if strings.Contains(wsURL, "?") {
		wsURL = wsURL + "&token=" + resp.Token
	} else {
		wsURL = wsURL + "?token=" + resp.Token
	}

	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(port))
	t, err := tunnel.ConnectClient(wsURL, targetAddr, tunnelUUID, skipTLSVerify, useTLS)
	if err != nil {
		fmt.Printf("\n  %s✗ %s%s\n\n", colorRed, err.Error(), colorReset)
		os.Exit(1)
	}

	go func() {
		if err := t.Process(); err != nil {
			errStr := err.Error()
			// Suppress raw websocket closure errors for cleaner exit
			if strings.Contains(errStr, "websocket: close 1006") ||
				strings.Contains(errStr, "EOF") ||
				strings.Contains(errStr, "connection reset") {
				fmt.Printf("\n  %s✗ Connection to server lost%s\n", colorRed, colorReset)
			} else {
				fmt.Printf("\n  %s✗ connection lost: %v%s\n", colorRed, err, colorReset)
			}
			os.Exit(1)
		}
	}()

	// Tunnel info display
	// Hide 8080 port in TUI for cleaner look (user request)
	displayMagicURL := strings.Replace(magicURL, ":8080", "", -1)
	displayPublicURL := strings.Replace(resp.URL, ":8080", "", -1)

	// Start dashboard
	dash := dashboard.New(constants.DashboardPort, displayPublicURL, t.Logger())
	if err := dash.Start(); err != nil {
		fmt.Printf("  %s⚠ Dashboard failed to start: %v%s\n", colorYellow, err, colorReset)
	}

	// Set dashboard for logging HTTP requests
	t.SetDashboard(dash)

	fmt.Println()
	fmt.Printf("  %s%s● tunnel active%s\n", colorBold, colorGreen, colorReset)
	fmt.Println()
	printField("magic url", displayMagicURL, colorCyan)
	printField("public url", displayPublicURL, colorYellow)
	dashboardURL := fmt.Sprintf("http://%s:%d", constants.DashboardHost, constants.DashboardPort)
	printField("dashboard", dashboardURL, colorPurple)
	printField("local", localAddr, colorReset)
	fmt.Println()
	printSep()
	fmt.Println()
	printField("expires", fmt.Sprintf("%s (%s)", expiresAt, durationDisplay), colorReset)
	if t.GetLogPath() != "" {
		printField("logs", t.GetLogPath(), colorDim)
	}
	fmt.Println()
	printSep()
	fmt.Println()
	fmt.Printf("  %smagic url  → direct access (no password)%s\n", colorDim, colorReset)
	fmt.Printf("  %spublic url → requires password%s\n", colorDim, colorReset)
	fmt.Printf("  %sdashboard  → view requests at %s:%d%s\n", colorDim, constants.DashboardHost, constants.DashboardPort, colorReset)
	fmt.Println()
	fmt.Printf("  %sctrl+c to stop%s\n", colorDim, colorReset)
	fmt.Println()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan

	fmt.Println()
	fmt.Printf("  %s● shutting down...%s\n", colorYellow, colorReset)
	t.Close()
	fmt.Printf("  %s● done%s\n\n", colorGreen, colorReset)
}

func registerTunnel(serverURL string, config types.ConfigRequest, skipTLSVerify bool) (*types.ConfigResponse, error) {
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

	var result types.ConfigResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}
