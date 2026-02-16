package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"ssrok/internal/client"
	"ssrok/internal/constants"
	"ssrok/internal/dashboard"
	"ssrok/internal/tunnel"
	"ssrok/internal/types"
	"ssrok/internal/utils"
)

const (
	colorRed    = constants.ColorRed
	colorYellow = constants.ColorYellow
)

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
		client.PrintBanner()
		os.Exit(0)
	}

	if *updateFlag {
		utils.RunUpdate()
	}

	if len(os.Args) < 2 {
		fmt.Println(constants.MsgUsage)
		fmt.Println(constants.MsgExample)
		os.Exit(1)
	}

	arg := os.Args[1]
	targetHost, targetPort, err := utils.ParseTarget(arg)
	if err != nil {
		fmt.Printf(colorRed+"Error: %s\n"+constants.ColorReset, err.Error())
		os.Exit(1)
	}

	serverURL := utils.GetEnv("SSROK_SERVER", constants.DefaultServerURL)
	serverURL = strings.TrimSuffix(serverURL, "/")

	useHTTPS := strings.HasPrefix(serverURL, "https://")
	skipTLSVerify := useHTTPS && (strings.Contains(serverURL, "localhost") ||
		strings.Contains(serverURL, "127.0.0.1") ||
		strings.Contains(serverURL, ".onrender.com") ||
		strings.Contains(serverURL, ".railway.app") ||
		strings.Contains(serverURL, ".fly.io"))

	client.PrintBanner()

	reader := bufio.NewReader(os.Stdin)

	client.PrintStep(1, "Local server configuration")
	client.PrintHint("Target: " + targetHost + ":" + strconv.Itoa(targetPort))
	fmt.Printf("  %sProtocol:%s ", constants.ColorBold, constants.ColorReset)

	useTLS := utils.DetectProtocol(targetHost, targetPort)
	if useTLS {
		fmt.Printf("%sHTTPS (auto-detected)%s\n", constants.ColorGreen, constants.ColorReset)
	} else {
		fmt.Printf("HTTP (auto-detected)\n")
	}

	client.PrintStep(2, "Password (optional)")
	client.PrintHint("Leave empty for 'No Password' login access")
	fmt.Printf("  %sPassword:%s ", constants.ColorBold, constants.ColorReset)
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	if password != "" && len(password) < 4 {
		fmt.Printf("  %smin 4 chars recommended%s\n", colorYellow, constants.ColorReset)
	}
	fmt.Println()

	client.PrintStep(3, "Rate limit (0 = unlimited)")
	fmt.Printf("  %sReq/min [%d]:%s ", constants.ColorBold, constants.DefaultRateLimit, constants.ColorReset)
	rateLimitStr, _ := reader.ReadString('\n')
	rateLimitStr = strings.TrimSpace(rateLimitStr)

	rateLimit := constants.DefaultRateLimit
	if rateLimitStr != "" {
		rl, err := strconv.Atoi(rateLimitStr)
		if err == nil && rl >= 0 {
			rateLimit = rl
			if rateLimit == 0 {
				client.PrintHint(colorYellow + "unlimited" + constants.ColorReset)
			} else {
				client.PrintHint(fmt.Sprintf("-> %d req/min per IP", rateLimit))
			}
		} else {
			client.PrintHint(fmt.Sprintf("-> default: %d req/min", constants.DefaultRateLimit))
		}
	}
	fmt.Println()

	client.PrintStep(4, "Duration (5-1440 min)")
	fmt.Printf("  %sMinutes [60]:%s ", constants.ColorBold, constants.ColorReset)
	durationStr, _ := reader.ReadString('\n')
	durationStr = strings.TrimSpace(durationStr)

	expiresIn := constants.SessionDuration
	if durationStr != "" {
		mins, err := strconv.Atoi(durationStr)
		if err == nil && mins > 0 {
			expiresIn = utils.ParseDuration(mins)
			if expiresIn < constants.MinSessionDuration {
				expiresIn = constants.MinSessionDuration
				client.PrintHint(fmt.Sprintf("-> clamped to %s", expiresIn))
			} else if expiresIn > constants.MaxSessionDuration {
				expiresIn = constants.MaxSessionDuration
				client.PrintHint(fmt.Sprintf("-> clamped to %s", expiresIn))
			} else {
				client.PrintHint(fmt.Sprintf("-> %d min", mins))
			}
		} else {
			client.PrintHint("-> default: 60 min")
		}
	}
	fmt.Println()

	client.PrintSep()
	fmt.Printf("  %sConnecting...%s\n", constants.ColorDim, constants.ColorReset)

	config := types.ConfigRequest{
		Port:      targetPort,
		Password:  password,
		RateLimit: rateLimit,
		UseTLS:    useTLS,
		ExpiresIn: expiresIn,
	}

	resp, err := utils.RegisterTunnel(serverURL, config, skipTLSVerify)
	if err != nil {
		if strings.HasPrefix(serverURL, "http://") && strings.Contains(err.Error(), "status 400") {
			client.PrintHint(colorYellow + "HTTP connection failed, attempting HTTPS..." + constants.ColorReset)
			serverURL = strings.Replace(serverURL, "http://", "https://", 1)

			skipTLSVerify = strings.Contains(serverURL, "localhost") || strings.Contains(serverURL, "127.0.0.1")

			resp, err = utils.RegisterTunnel(serverURL, config, skipTLSVerify)
		}
	}

	if err != nil {
		fmt.Println()
		fmt.Println(colorRed + "   Failed to connect: " + err.Error() + constants.ColorReset)
		fmt.Println()
		os.Exit(1)
	}

	magicURL := fmt.Sprintf("%s?token=%s", resp.URL, resp.Token)
	localProto := "http"
	if useTLS {
		localProto = "https"
	}
	localAddr := fmt.Sprintf("%s://%s:%d", localProto, targetHost, targetPort)
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

	targetAddr := fmt.Sprintf("%s:%d", targetHost, targetPort)
	t, err := tunnel.ConnectClient(wsURL, targetAddr, tunnelUUID, skipTLSVerify, useTLS)
	if err != nil {
		fmt.Printf("\n  %s%s%s\n\n", colorRed, err.Error(), constants.ColorReset)
		os.Exit(1)
	}

	go func() {
		if err := t.Process(); err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "websocket: close 1006") ||
				strings.Contains(errStr, "EOF") ||
				strings.Contains(errStr, "connection reset") {
			}
			os.Exit(1)
		}
	}()

	displayMagicURL := strings.Replace(magicURL, ":8080", "", -1)
	displayPublicURL := strings.Replace(resp.URL, ":8080", "", -1)
	dashboardURL := fmt.Sprintf("http://%s:%d", constants.DashboardHost, constants.DashboardPort)

	dash := dashboard.New(constants.DashboardPort, displayPublicURL, t.Logger())
	if err := dash.Start(); err == nil {
		t.SetDashboard(dash)
	}

	client.StartTUI(t, displayPublicURL, displayMagicURL, dashboardURL, localAddr, expiresAt, durationDisplay, t.GetLogPath())
}
