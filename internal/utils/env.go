package utils

import "os"

// GetEnv returns environment variable value or default if empty
func GetEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}
