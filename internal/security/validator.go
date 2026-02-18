package security

import (
	"html"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

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

func SanitizeHTML(input string) string {
	return html.EscapeString(input)
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

var dangerousChars = []string{
	";", "|", "&", "$", "`", "(", ")", "{", "}", "[", "]",
	"<", ">", "'", "\"", "\\", "\n", "\r", "\x00",
}

var dangerousKeywords = []string{
	"exec", "eval", "system", "passthru", "shell_exec", "popen", "proc_open",
	"base64_decode", "assert", "create_function", "call_user_func",
	"preg_replace", "include", "require", "include_once", "require_once",
	"wget", "curl", "nc", "netcat", "telnet", "ssh", "scp", "sftp",
	"rm", "mv", "cp", "chmod", "chown", "kill", "pkill", "killall",
	"cat", "head", "tail", "less", "more", "nano", "vim", "vi",
	"/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash",
	"python", "perl", "ruby", "php", "node", "nodejs",
	"select", "insert", "update", "delete", "drop", "union", "truncate",
}

var commandInjectionRegex = regexp.MustCompile(`(?i)(` + strings.Join(dangerousKeywords, `|`) + `)`)

func DetectCommandInjection(values ...string) bool {
	for _, v := range values {
		lowerV := strings.ToLower(v)

		for _, char := range dangerousChars {
			if strings.Contains(v, char) {
				if !isAllowedChar(v, char) {
					return true
				}
			}
		}

		if commandInjectionRegex.MatchString(lowerV) {
			if !isInSafeContext(v, lowerV) {
				return true
			}
		}
	}
	return false
}

func isAllowedChar(value, char string) bool {
	safePatterns := []string{
		".html", ".css", ".js", ".json", ".xml", ".txt",
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
		".woff", ".woff2", ".ttf", ".eot", ".otf", ".webp",
		".mp4", ".webm", ".mp3", ".wav", ".pdf", ".zip",
		"text/html", "application/json", "text/plain",
	}

	lowerValue := strings.ToLower(value)
	for _, pattern := range safePatterns {
		if strings.Contains(lowerValue, pattern) {
			return true
		}
	}
	return false
}

func isInSafeContext(original, lowerValue string) bool {
	safeContexts := []string{
		"content-type",
		"accept",
		"user-agent",
		"referer",
		"filename=",
		".exec.",
		".exe",
	}

	for _, ctx := range safeContexts {
		if strings.Contains(lowerValue, ctx) {
			return true
		}
	}
	return false
}

func ValidateStringLength(s string, minLen, maxLen int) bool {
	length := utf8.RuneCountInString(s)
	return length >= minLen && length <= maxLen
}

func IsPrintableASCII(s string) bool {
	for _, r := range s {
		if r < 32 || r > 126 {
			if r != '\n' && r != '\r' && r != '\t' {
				return false
			}
		}
	}
	return true
}
