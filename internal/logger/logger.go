package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

type LogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	Direction  string    `json:"direction"`
	Type       string    `json:"type"`
	Size       int       `json:"size"`
	RemoteAddr string    `json:"remote_addr,omitempty"`
	LocalPort  int       `json:"local_port,omitempty"`
	Error      string    `json:"error,omitempty"`
	Message    string    `json:"message,omitempty"`
}

type Logger struct {
	mu        sync.RWMutex
	file      *os.File
	enc       *json.Encoder
	logDir    string
	sessionID string
}

func NewLogger(sessionID string) (*Logger, error) {
	logDir, err := getLogDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get log directory: %w", err)
	}

	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	logFile := filepath.Join(logDir, fmt.Sprintf("%s.log", sessionID))

	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	return &Logger{
		file:      file,
		enc:       json.NewEncoder(file),
		logDir:    logDir,
		sessionID: sessionID,
	}, nil
}

func getLogDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	var logDir string
	switch runtime.GOOS {
	case "windows":
		logDir = filepath.Join(homeDir, "AppData", "Local", "ssrok", "logs")
	case "darwin":
		logDir = filepath.Join(homeDir, "Library", "Logs", "ssrok")
	default: // linux and others
		logDir = filepath.Join(homeDir, ".local", "share", "ssrok", "logs")
		// Use XDG_DATA_HOME if set
		if xdgData := os.Getenv("XDG_DATA_HOME"); xdgData != "" {
			logDir = filepath.Join(xdgData, "ssrok", "logs")
		}
	}

	return logDir, nil
}

func (l *Logger) Log(entry LogEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry.Timestamp = time.Now()
	l.enc.Encode(entry)
}

func (l *Logger) LogData(direction string, data []byte, remoteAddr string, localPort int) {
	l.Log(LogEntry{
		Direction:  direction,
		Type:       "data",
		Size:       len(data),
		RemoteAddr: remoteAddr,
		LocalPort:  localPort,
	})
}

func (l *Logger) LogError(direction string, err error, remoteAddr string, localPort int) {
	l.Log(LogEntry{
		Direction:  direction,
		Type:       "error",
		Error:      err.Error(),
		RemoteAddr: remoteAddr,
		LocalPort:  localPort,
	})
}

func (l *Logger) LogEvent(message string, localPort int) {
	l.Log(LogEntry{
		Direction: "client",
		Type:      "event",
		Message:   message,
		LocalPort: localPort,
	})
}

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

func (l *Logger) GetLogPath() string {
	if l.file != nil {
		return l.file.Name()
	}
	return ""
}

func (l *Logger) GetLogDir() string {
	return l.logDir
}

func (l *Logger) GetSessionID() string {
	return l.sessionID
}
