package main

import (
	"flag"
	"fmt"
	"os"

	"ssrok/internal/constants"
	"ssrok/internal/server"
	"ssrok/internal/utils"
)

func main() {
	versionFlag := flag.Bool("version", false, "show version")
	updateFlag := flag.Bool("update", false, "update ssrok")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("ssrok server v%s\n", constants.Version)
		os.Exit(0)
	}

	if *updateFlag {
		utils.RunUpdate()
	}

	s, err := server.NewServer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize server: %v\n", err)
		os.Exit(1)
	}

	s.Run()
}
