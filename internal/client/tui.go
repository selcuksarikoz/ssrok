package client

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

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

func StartTUI(t *tunnel.Tunnel, publicURL, magicURL, dashboardURL, localAddr, expiresAt, durationDisplay, logPath string) {
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
		fmt.Print("\033[?25h")
		fmt.Println()
		fmt.Printf("  %s● disconnected%s\n", ColorRed, ColorReset)
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
			RenderTUI(t, publicURL, magicURL, dashboardURL, localAddr, expiresAt, durationDisplay, logPath, logBuffer)
		case <-sigChan:
			return
		}
	}
}

func RenderTUI(t *tunnel.Tunnel, publicURL, magicURL, dashboardURL, localAddr, expiresAt, durationDisplay, logPath string, logs []string) {
	fmt.Print("\033[H")

	fmt.Printf("  %s%sssrok%s %sv%s%s\n", constants.ColorBold, constants.ColorCyan, constants.ColorReset, constants.ColorBold, constants.Version, constants.ColorReset)
	fmt.Printf("  %sSecure Ephemeral Reverse Proxy%s\n", constants.ColorDim, constants.ColorReset)
	fmt.Println()

	bytesIn := atomic.LoadInt64(&t.BytesIn)
	bytesOut := atomic.LoadInt64(&t.BytesOut)
	totalReqs := atomic.LoadInt64(&t.TotalReqs)
	activeConns := atomic.LoadInt64(&t.ActiveConns)

	fmt.Printf("  %sRecved: %s%10s%s   %sSent: %s%10s%s\n",
		ColorDim, ColorReset, utils.FormatBytes(bytesIn), ColorReset,
		ColorDim, ColorReset, utils.FormatBytes(bytesOut), ColorReset)
	fmt.Printf("  %sReq:    %s%10d%s   %sActive: %s%8d%s\n",
		ColorDim, ColorReset, totalReqs, ColorReset,
		ColorDim, ColorReset, activeConns, ColorReset)
	fmt.Println()

	PrintField("magic url", magicURL, ColorCyan)
	PrintField("public url", publicURL, ColorYellow)
	PrintField("dashboard", dashboardURL, ColorPurple)
	PrintField("local", localAddr, ColorReset)
	PrintField("expires", fmt.Sprintf("%s (%s)", expiresAt, durationDisplay), ColorReset)
	if logPath != "" {
		PrintField("logs", logPath, ColorDim)
	}

	fmt.Println()
	fmt.Printf("  %s%s%s\n", ColorDim, strings.Repeat("─", 50), ColorReset)

	for _, log := range logs {
		fmt.Printf("\033[K%s\n", log)
	}

	fmt.Print("\033[J")
}
