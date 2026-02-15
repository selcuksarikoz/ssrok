package security

import (
	"net/http"
	"regexp"
	"strings"
)

var uuidRegex = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ValidateUUID checks if string is valid UUID format
func ValidateUUID(uuid string) bool {
	if uuid == "" {
		return false
	}
	return uuidRegex.MatchString(strings.ToLower(uuid))
}

// ValidateToken checks token format (should be UUID-like)
func ValidateToken(token string) bool {
	if token == "" || len(token) < 32 {
		return false
	}
	return true
}

// ValidatePort checks if port is valid
func ValidatePort(port int) bool {
	return port > 0 && port <= 65535
}

// ValidateOrigin checks if request origin is allowed
func ValidateOrigin(r *http.Request, allowedOrigins []string) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // No origin header = same origin or direct request
	}

	if len(allowedOrigins) == 0 {
		return true // Allow all if no restriction set
	}

	for _, allowed := range allowedOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}

	return false
}

// SanitizeInput removes potentially dangerous characters
func SanitizeInput(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")
	// Remove control characters except newline/tab
	var result strings.Builder
	for _, r := range input {
		if r >= 32 || r == '\n' || r == '\t' || r == '\r' {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// ValidatePath checks for path traversal attempts
func ValidatePath(path string) bool {
	// Check for path traversal
	if strings.Contains(path, "..") {
		return false
	}
	// Check for null bytes
	if strings.Contains(path, "\x00") {
		return false
	}
	return true
}

// MaxBodySize middleware limits request body size
func MaxBodySize(maxSize int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxSize)
			next.ServeHTTP(w, r)
		})
	}
}
