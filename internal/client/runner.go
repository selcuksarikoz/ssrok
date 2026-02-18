package client

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"ssrok/internal/constants"
	"ssrok/internal/dashboard"
	"ssrok/internal/tunnel"
	"ssrok/internal/types"
	"ssrok/internal/utils"
)

var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripANSI(s string) string {
	return ansiRegex.ReplaceAllString(s, "")
}

// Start initializes the client, runs the wizard, and manages the tunnel lifecycle
func Start(targetHost string, targetPort int, useTLS bool) {
	serverURL := utils.GetEnv("SSROK_SERVER", constants.DefaultServerURL)
	serverURL, skipTLSVerify := utils.NormalizeServerURL(serverURL)

	PrintBanner()

	config := RunConfigWizard(targetHost, targetPort, useTLS)

	PrintSep()
	PrintHint(ColorGreen + "🔒 E2EE Active (ChaCha20-Poly1305)" + ColorReset)
	fmt.Printf("  %sConnecting...%s\n", ColorDim, ColorReset)

	resp, err := utils.RegisterTunnel(serverURL, config, skipTLSVerify)
	if err != nil {
		if strings.HasPrefix(serverURL, "http://") && strings.Contains(err.Error(), "status 400") {
			PrintHint(ColorYellow + "HTTP connection failed, attempting HTTPS..." + ColorReset)
			serverURL = strings.Replace(serverURL, "http://", "https://", 1)
			_, skipTLSVerify = utils.NormalizeServerURL(serverURL)
			resp, err = utils.RegisterTunnel(serverURL, config, skipTLSVerify)
		}
	}

	if err != nil {
		fmt.Println()
		fmt.Printf("   %sFailed to connect: %s%s\n", ColorRed, err.Error(), ColorReset)
		fmt.Println()
		os.Exit(1)
	}

	wsURL := utils.ConstructWSURL(resp.URL, resp.Token, resp.UUID)
	tunnelUUID := resp.UUID
	if tunnelUUID == "" {
		tunnelUUID = utils.ExtractUUID(resp.URL)
	}

	targetAddr := fmt.Sprintf("%s:%d", targetHost, targetPort)
	t, err := tunnel.ConnectClient(wsURL, targetAddr, tunnelUUID, skipTLSVerify, useTLS, config.E2EE)
	if err != nil {
		fmt.Printf("\n  %s%s%s\n\n", ColorRed, err.Error(), ColorReset)
		os.Exit(1)
	}

	go func() {
		if err := t.Process(); err != nil {
			errStr := err.Error()
			if strings.Contains(errStr, "server closed") {
				fmt.Println()
				PrintHint(ColorYellow + "Server closed the connection" + ColorReset)
			} else {
				fmt.Println()
				fmt.Printf("   %sError: %s%s\n", ColorRed, errStr, ColorReset)
			}
			os.Exit(1)
		}
	}()

	expiresAt := time.Now().Add(resp.ExpiresIn).Format(constants.TimeFormatShort)
	durationDisplay := utils.FormatDuration(resp.ExpiresIn)

	magicURL := fmt.Sprintf("%s?token=%s", resp.URL, resp.Token)
	displayMagicURL := strings.Replace(magicURL, ":8080", "", -1)
	displayPublicURL := strings.Replace(resp.URL, ":8080", "", -1)
	dashboardURL := fmt.Sprintf("http://%s:%d", constants.DashboardHost, constants.DashboardPort)

	dash := dashboard.New(constants.DashboardPort, displayPublicURL, t.Logger(), t.GetLogPath())
	if err := dash.Start(); err == nil {
		t.SetDashboard(dash)
	}

	t.LogCallback = func(string) {}
	t.SecurityCallback = func(msg string) {
		if dash != nil {
			cleanMsg := stripANSI(msg)
			parts := strings.Fields(cleanMsg)
			if len(parts) >= 4 {
				dash.AddSecurityEvent(types.SecurityEvent{
					ID:        uuid.New().String(),
					EventType: parts[1],
					IP:        parts[3],
					Details:   msg,
					Severity:  "warning",
					Timestamp: time.Now(),
				})
			}
		}
	}

	StartTUI(t, displayPublicURL, displayMagicURL, dashboardURL, expiresAt, durationDisplay)
}
