package utils

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"ssrok/internal/constants"
)

func FormatDuration(d time.Duration) string {
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60

	if hours == 0 {
		return fmt.Sprintf("%d minutes", minutes)
	}
	if minutes == 0 {
		if hours == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", hours)
	}
	if hours == 1 {
		return fmt.Sprintf("1 hour %d minutes", minutes)
	}
	return fmt.Sprintf("%d hours %d minutes", hours, minutes)
}

func ExtractUUID(tunnelURL string) string {
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

// FormatLog returns a standardized log string for the application.
// If emoji is empty, it is automatically selected based on the status code.
func FormatLog(emoji string, method string, statusCode int, path string) string {
	if emoji == "" {
		if statusCode >= 200 && statusCode < 300 {
			emoji = "✅"
		} else if statusCode >= 400 {
			emoji = "❌"
		} else if statusCode >= 300 {
			emoji = "🔄"
		} else {
			emoji = "📥"
		}
	}

	return fmt.Sprintf("  %s %s%s %d %s%s\n",
		emoji,
		constants.ColorDim,
		method,
		statusCode,
		path,
		constants.ColorReset,
	)
}
