package utils

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"ssrok/internal/constants"
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

// IsDefaultPort returns true if the port is a standard web port (80, 443)
func IsDefaultPort(port string) bool {
	return constants.StandardWebPorts[port]
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

// Respond responds to the request with either JSON or HTML based on Accept header
func Respond(w http.ResponseWriter, r *http.Request, statusCode int, message string, renderFunc func(string)) {
	accept := r.Header.Get("Accept")

	if strings.Contains(accept, "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		json.NewEncoder(w).Encode(map[string]string{"error": message})
		return
	}

	if renderFunc != nil {
		w.WriteHeader(statusCode)
		renderFunc(message)
		return
	}

	http.Error(w, message, statusCode)
}
