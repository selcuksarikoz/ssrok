package utils

import (
	"strings"
)

// NormalizeServerURL trims trailing slash and determines if TLS verification should be skipped
func NormalizeServerURL(serverURL string) (string, bool) {
	serverURL = strings.TrimSuffix(serverURL, "/")
	useHTTPS := strings.HasPrefix(serverURL, "https://")
	skipTLSVerify := useHTTPS && (strings.Contains(serverURL, "localhost") ||
		strings.Contains(serverURL, "127.0.0.1") ||
		strings.Contains(serverURL, ".onrender.com") ||
		strings.Contains(serverURL, ".railway.app") ||
		strings.Contains(serverURL, ".fly.io"))
	return serverURL, skipTLSVerify
}

// ConstructWSURL builds the WebSocket URL from the base URL and session details
func ConstructWSURL(respURL, token, uuid string) string {
	wsURL := respURL
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

	if uuid == "" {
		uuid = ExtractUUID(respURL)
	}

	wsURL = strings.Replace(wsURL, "/"+uuid, "/ws/"+uuid, 1)
	if strings.Contains(wsURL, "?") {
		wsURL = wsURL + "&token=" + token
	} else {
		wsURL = wsURL + "?token=" + token
	}
	return wsURL
}
