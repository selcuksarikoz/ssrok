package utils

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

func init() {
	// Support custom config file for development testing (e.g. SSROK_CONFIG_FILE=.env.prod)
	configFile := os.Getenv("SSROK_CONFIG_FILE")

	if configFile != "" {
		if err := godotenv.Load(configFile); err != nil {
			log.Printf("Warning: Failed to load config from %s: %v", configFile, err)
		} else {
			log.Printf("Loaded configuration from %s", configFile)
		}
	} else {
		// Default behavior: try to load .env file
		if err := godotenv.Load(); err != nil {
			// .env file is optional in production if using system env vars
		} else {
			log.Println("Loaded configuration from .env file")
		}
	}
}

// GetEnv returns environment variable value or default if empty
func GetEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}
