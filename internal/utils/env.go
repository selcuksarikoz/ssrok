package utils

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

func init() {
	// Try to load .env file, but don't fail if it doesn't exist
	if err := godotenv.Load(); err != nil {
	} else {
		log.Println("Loaded configuration from .env file")
	}
}

// GetEnv returns environment variable value or default if empty
func GetEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}
