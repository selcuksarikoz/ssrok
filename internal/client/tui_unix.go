//go:build !windows
// +build !windows

package client

import (
	"os"
	"os/signal"
	"syscall"
)

func setupSignals(sigChan chan os.Signal) chan os.Signal {
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	winchChan := make(chan os.Signal, 1)
	signal.Notify(winchChan, syscall.SIGWINCH)
	return winchChan
}

func handleWinch(winchChan chan os.Signal) bool {
	select {
	case <-winchChan:
		return true
	default:
		return false
	}
}
