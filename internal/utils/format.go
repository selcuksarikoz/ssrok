package utils

import (
	"fmt"
	"net/url"
	"strings"
	"time"
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
