package main

import (
	"log"

	"ssrok/internal/server"
)

func main() {
	s, err := server.NewServer()
	if err != nil {
		log.Fatalf("Failed to initialize server: %v", err)
	}

	s.Run()
}
