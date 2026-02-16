package utils

import (
	"fmt"
	"os"
	"os/exec"

	"ssrok/internal/constants"
)

func RunUpdate() {
	fmt.Println("  Checking for updates via Homebrew...")

	checkCmd := exec.Command("brew", "--version")
	if err := checkCmd.Run(); err != nil {
		fmt.Printf("  %sHomebrew not found. Please install Homebrew first:%s\n", constants.ColorYellow, constants.ColorReset)
		fmt.Println("  https://brew.sh")
		os.Exit(1)
	}

	fmt.Println("  Running: brew update && brew upgrade ssrok")
	fmt.Println()

	cmd := exec.Command("brew", "update")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()

	cmd = exec.Command("brew", "upgrade", "ssrok")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("  %sUpgrade failed or ssrok not installed%s\n", constants.ColorYellow, constants.ColorReset)
		fmt.Println("  Try: brew install ssrok")
		os.Exit(1)
	}

	fmt.Println()
	fmt.Printf("  %sUpdate complete!%s\n", constants.ColorGreen, constants.ColorReset)
	os.Exit(0)
}
