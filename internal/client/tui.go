package client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/skip2/go-qrcode"

	"ssrok/internal/constants"
	"ssrok/internal/tunnel"
	"ssrok/internal/utils"
)

const (
	ColorReset  = constants.ColorReset
	ColorBold   = constants.ColorBold
	ColorDim    = constants.ColorDim
	ColorCyan   = constants.ColorCyan
	ColorGreen  = constants.ColorGreen
	ColorYellow = constants.ColorYellow
	ColorRed    = constants.ColorRed
	ColorPurple = constants.ColorPurple
)

func PrintBanner() {
	fmt.Println()
	fmt.Printf("  %s%sssrok%s %sv%s%s\n", constants.ColorBold, constants.ColorCyan, constants.ColorReset, constants.ColorBold, constants.Version, constants.ColorReset)
	fmt.Printf("  %sSecure Ephemeral Reverse Proxy%s\n", constants.ColorDim, constants.ColorReset)
	fmt.Printf("  %s⚠️  This is a proxy - cannot verify request source. Handle with caution.%s\n", ColorYellow, ColorReset)
	fmt.Println()
}

func PrintHint(text string) {
	fmt.Printf("  %s%s%s\n", ColorDim, text, ColorReset)
}

func PrintStep(number int, text string) {
	fmt.Printf("  %s%s▸%s %s\n", ColorBold, ColorCyan, ColorReset, text)
}

func PrintField(label, value, valueColor string) {
	fmt.Printf("  %s%-12s%s %s%s%s\n", ColorDim, label, ColorReset, valueColor, value, ColorReset)
}

func PrintSep() {
	fmt.Printf("  %s%s%s\n", ColorDim, strings.Repeat("─", 50), ColorReset)
}

func StartTUI(t *tunnel.Tunnel, publicURL, magicURL, dashboardURL, expiresAt, durationDisplay string) {
	fmt.Print("\033?25l")
	fmt.Print("\033[2J")

	qr, _ := qrcode.New(magicURL, qrcode.Low)
	qr.DisableBorder = true
	qrStr := qr.ToSmallString(false)

	ticker := time.NewTicker(200 * time.Millisecond)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	winchChan := make(chan os.Signal, 1)
	signal.Notify(winchChan, syscall.SIGWINCH)

	dashStatsChan := make(chan int64, 1)
	go func() {
		for {
			select {
			case <-sigChan:
				return
			case <-time.After(2 * time.Second):
				resp, err := http.Get(fmt.Sprintf("http://%s/api/stats", dashboardURL))
				if err == nil {
					var stats map[string]interface{}
					if json.NewDecoder(resp.Body).Decode(&stats) == nil {
						if v, ok := stats["active_requests"].(float64); ok {
							select {
							case dashStatsChan <- int64(v):
							default:
							}
						}
					}
					resp.Body.Close()
				}
			}
		}
	}()

	defer func() {
		ticker.Stop()
		t.Close()
		fmt.Print("\033[?25h")
		fmt.Println()
		fmt.Printf("  %s● disconnected%s\n", ColorRed, ColorReset)
	}()

	for {
		select {
		case activeDash := <-dashStatsChan:
			RenderTUI(t, publicURL, magicURL, qrStr, dashboardURL, expiresAt, durationDisplay, activeDash, false)
		case <-ticker.C:
			RenderTUI(t, publicURL, magicURL, qrStr, dashboardURL, expiresAt, durationDisplay, 0, false)
		case <-winchChan:
			RenderTUI(t, publicURL, magicURL, qrStr, dashboardURL, expiresAt, durationDisplay, 0, true)
		case <-sigChan:
			return
		}
	}
}

func RenderTUI(t *tunnel.Tunnel, publicURL, magicURL, qrStr, dashboardURL, expiresAt, durationDisplay string, activeFromDash int64, clearScreen bool) {
	if clearScreen {
		fmt.Print("\033[2J")
	}
	fmt.Print("\033[H")

	fmt.Printf("  %s%sssrok%s %sv%s%s\n", constants.ColorBold, constants.ColorCyan, constants.ColorReset, constants.ColorBold, constants.Version, constants.ColorReset)
	fmt.Printf("  %sSecure Ephemeral Reverse Proxy%s\n", constants.ColorDim, ColorReset)
	fmt.Println()

	bytesIn := atomic.LoadInt64(&t.BytesIn)
	bytesOut := atomic.LoadInt64(&t.BytesOut)
	totalReqs := atomic.LoadInt64(&t.TotalReqs)
	activeConns := atomic.LoadInt64(&t.ActiveConns)
	blocked := atomic.LoadInt64(&t.Blocked)
	rateLimited := atomic.LoadInt64(&t.RateLimited)
	if activeFromDash > activeConns {
		activeConns = activeFromDash
	}

	fmt.Printf("  %sRecved:%s %s%8s%s  %sSent:%s %s%8s%s  %sReq:%s %s%8d%s\n",
		ColorDim, ColorReset, ColorBold, utils.FormatBytes(bytesIn), ColorReset,
		ColorDim, ColorReset, ColorBold, utils.FormatBytes(bytesOut), ColorReset,
		ColorDim, ColorReset, ColorBold, totalReqs, ColorReset)
	fmt.Printf("  %sActive:%s %s%8d%s  %sBlocked:%s %s%8d%s  %sRateLimit:%s %s%8d%s\n",
		ColorDim, ColorReset, ColorBold, activeConns, ColorReset,
		ColorDim, ColorReset, ColorBold, blocked, ColorReset,
		ColorDim, ColorReset, ColorBold, rateLimited, ColorReset)
	fmt.Println()
	PrintField("magic url", magicURL, ColorCyan)
	PrintField("public url", publicURL, ColorYellow)
	PrintField("dashboard", dashboardURL, ColorPurple)
	PrintField("expires", fmt.Sprintf("%s (%s)", expiresAt, durationDisplay), ColorReset)

	fmt.Println()
	fmt.Print(qrStr)
	fmt.Println()

	fmt.Print("\033[J")
}
