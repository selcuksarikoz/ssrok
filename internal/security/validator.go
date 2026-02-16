package security

import (
	"net/http"
	"regexp"
	"strings"

	"ssrok/internal/constants"
)

var uuidRegex = regexp.MustCompile(constants.DefaultUUIDRegex)

func ValidateUUID(uuid string) bool {
	if uuid == "" {
		return false
	}
	return uuidRegex.MatchString(strings.ToLower(uuid))
}

func ValidateToken(token string) bool {
	return token != "" && len(token) >= constants.MinTokenLength
}

func ValidatePort(port int) bool {
	return port >= constants.MinPort && port <= constants.MaxPort
}

func ValidateOrigin(r *http.Request, allowedOrigins []string) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}

	if len(allowedOrigins) == 0 {
		return true
	}

	for _, allowed := range allowedOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}

	return false
}

func SanitizeInput(input string) string {
	input = strings.ReplaceAll(input, "\x00", "")
	var result strings.Builder
	for _, r := range input {
		if r >= 32 || r == '\n' || r == '\t' || r == '\r' {
			result.WriteRune(r)
		}
	}
	return result.String()
}

func ValidatePath(path string) bool {
	if strings.Contains(path, "..") {
		return false
	}
	if strings.Contains(path, "\x00") {
		return false
	}
	return true
}

func MaxBodySize(maxSize int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxSize)
			next.ServeHTTP(w, r)
		})
	}
}
