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
	"sync/atomic"
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
	fmt.Printf("  %sProtocol:%s ", colorBold, colorReset)

	// Auto-detect local protocol
	useTLS := detectProtocol(targetHost, port)
	if useTLS {
		fmt.Printf("%sHTTPS (auto-detected)%s\n", colorGreen, colorReset)
	} else {
		fmt.Printf("HTTP (auto-detected)\n")
	}

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
				// handled by TUI exit usually, but if TUI active..
			} else {
				// handle error
			}
			os.Exit(1)
		}
	}()

	// Hide 8080 port in TUI for cleaner look
	displayMagicURL := strings.Replace(magicURL, ":8080", "", -1)
	displayPublicURL := strings.Replace(resp.URL, ":8080", "", -1)
	dashboardURL := fmt.Sprintf("http://%s:%d", constants.DashboardHost, constants.DashboardPort)

	// Start dashboard
	dash := dashboard.New(constants.DashboardPort, displayPublicURL, t.Logger())
	if err := dash.Start(); err == nil {
		t.SetDashboard(dash)
	}

	// Start TUI
	startTUI(t, displayPublicURL, displayMagicURL, dashboardURL, localAddr, expiresAt, durationDisplay, t.GetLogPath())
}

func startTUI(t *tunnel.Tunnel, publicURL, magicURL, dashboardURL, localAddr, expiresAt, durationDisplay, logPath string) {
	// Hide cursor and clear screen
	fmt.Print("\033[?25l")
	fmt.Print("\033[2J")

	logChan := make(chan string, 100)
	t.LogCallback = func(msg string) {
		select {
		case logChan <- msg:
		default:
		}
	}

	logBuffer := make([]string, 0, 15)

	ticker := time.NewTicker(200 * time.Millisecond)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	defer func() {
		ticker.Stop()
		t.Close()
		fmt.Print("\033[?25h") // Show cursor
		fmt.Println()
		fmt.Printf("  %s● disconnected%s\n", colorRed, colorReset)
	}()

	for {
		select {
		case msg := <-logChan:
			msg = strings.TrimSuffix(msg, "\n")
			logBuffer = append(logBuffer, msg)
			if len(logBuffer) > 15 {
				logBuffer = logBuffer[1:]
			}
		case <-ticker.C:
			renderTUI(t, publicURL, magicURL, dashboardURL, localAddr, expiresAt, durationDisplay, logPath, logBuffer)
		case <-sigChan:
			return
		}
	}
}

func renderTUI(t *tunnel.Tunnel, publicURL, magicURL, dashboardURL, localAddr, expiresAt, durationDisplay, logPath string, logs []string) {
	// Reset cursor to top-left
	fmt.Print("\033[H")

	// Header
	fmt.Printf("  %s%sssrok%s %sv%s%s\n", constants.ColorBold, constants.ColorCyan, constants.ColorReset, constants.ColorBold, constants.Version, constants.ColorReset)
	fmt.Printf("  %sSecure Ephemeral Reverse Proxy%s\n", constants.ColorDim, constants.ColorReset)
	fmt.Println()

	// Stats Grid
	bytesIn := atomic.LoadInt64(&t.BytesIn)
	bytesOut := atomic.LoadInt64(&t.BytesOut)
	totalReqs := atomic.LoadInt64(&t.TotalReqs)
	activeConns := atomic.LoadInt64(&t.ActiveConns)

	fmt.Printf("  %sRecved: %s%10s%s   %sSent: %s%10s%s\n",
		colorDim, colorReset, formatBytes(bytesIn), colorReset,
		colorDim, colorReset, formatBytes(bytesOut), colorReset)
	fmt.Printf("  %sReq:    %s%10d%s   %sActive: %s%8d%s\n",
		colorDim, colorReset, totalReqs, colorReset,
		colorDim, colorReset, activeConns, colorReset)
	fmt.Println()

	// Info
	printField("magic url", magicURL, colorCyan)
	printField("public url", publicURL, colorYellow)
	printField("dashboard", dashboardURL, colorPurple)
	printField("local", localAddr, colorReset)
	printField("expires", fmt.Sprintf("%s (%s)", expiresAt, durationDisplay), colorReset)
	if logPath != "" {
		printField("logs", logPath, colorDim)
	}

	fmt.Println()
	fmt.Printf("  %s%s%s\n", colorDim, strings.Repeat("─", 50), colorReset)

	// Logs area - Clear remaining screen first to remove old logs if list shrunk (unlikely) or resized
	// Actually better to just print fixed lines.
	// We'll print "Recent Requests" header
	// fmt.Printf("  %sRecent Requests%s\n", colorDim, colorReset)

	for _, log := range logs {
		// Clear line before printing to handle varying lengths
		fmt.Printf("\033[K%s\n", log)
	}

	// Clear rest of screen roughly
	fmt.Print("\033[J")
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
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

func detectProtocol(host string, port int) bool {
	target := fmt.Sprintf("%s:%d", host, port)

	// Create a Dialer with a timeout
	dialer := &net.Dialer{
		Timeout: 2 * time.Second,
	}

	// Try to connect via TLS
	conn, err := tls.DialWithDialer(dialer, "tcp", target, &tls.Config{
		InsecureSkipVerify: true,
	})

	if err == nil {
		conn.Close()
		return true // It accepted a TLS handshake -> HTTPS
	}

	return false // Fallback to HTTP
}
