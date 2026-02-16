package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"ssrok/internal/types"
)

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
	default:
		logDir = filepath.Join(homeDir, ".local", "share", "ssrok", "logs")
		if xdgData := os.Getenv("XDG_DATA_HOME"); xdgData != "" {
			logDir = filepath.Join(xdgData, "ssrok", "logs")
		}
	}

	return logDir, nil
}

func (l *Logger) Log(entry types.HTTPLog) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry.Timestamp = time.Now()
	l.enc.Encode(entry)
}

func (l *Logger) LogData(direction string, data []byte, remoteAddr string, localPort int) {
	l.Log(types.HTTPLog{
		Method:     direction,
		Path:       "data",
		StatusCode: len(data),
		Timestamp:  time.Now(),
	})
}

func (l *Logger) LogError(direction string, err error, remoteAddr string, localPort int) {
	l.Log(types.HTTPLog{
		Method:     direction,
		Path:       "error",
		StatusCode: 0,
		Timestamp:  time.Now(),
	})
}

func (l *Logger) LogEvent(message string, localPort int) {
	l.Log(types.HTTPLog{
		Method:    "event",
		Path:      message,
		Timestamp: time.Now(),
	})
}

func (l *Logger) LogHTTP(method, path string, statusCode int, duration time.Duration, userAgent string, localPort int) {
	l.Log(types.HTTPLog{
		Method:     method,
		Path:       path,
		StatusCode: statusCode,
		Duration:   duration,
		UserAgent:  userAgent,
		Timestamp:  time.Now(),
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
