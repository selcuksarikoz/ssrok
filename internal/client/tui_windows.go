//go:build windows
// +build windows

package client

import (
	"os"
	"os/signal"
	"syscall"
)

func setupSignals(sigChan chan os.Signal) chan os.Signal {
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	return make(chan os.Signal) // empty channel that never receives
}

func handleWinch(winchChan chan os.Signal) bool {
	return false
}
