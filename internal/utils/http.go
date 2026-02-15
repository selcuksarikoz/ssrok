package utils

import (
	"fmt"
	"net/http"
	"strings"
)

// GetScheme determines the scheme (http/https) from the request
func GetScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if scheme := r.Header.Get("X-Forwarded-Proto"); scheme != "" {
		return scheme
	}
	return "http"
}

// standardWebPorts are ports that don't need to be shown in URLs
// 80 = HTTP, 443 = HTTPS
var standardWebPorts = map[string]bool{
	"80":  true,
	"443": true,
}

// IsDefaultPort returns true if the port is a standard web port (80, 443, 8080)
func IsDefaultPort(port string) bool {
	return standardWebPorts[port]
}

// ConstructURL builds a URL string and removes standard web ports if present
func ConstructURL(scheme, host, path string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	hostname := host
	port := ""

	if strings.Contains(host, ":") {
		parts := strings.Split(host, ":")
		if len(parts) == 2 {
			hostname = parts[0]
			port = parts[1]
		}
	}

	if port == "" || IsDefaultPort(port) {
		return fmt.Sprintf("%s://%s%s", scheme, hostname, path)
	}

	return fmt.Sprintf("%s://%s:%s%s", scheme, hostname, port, path)
}
