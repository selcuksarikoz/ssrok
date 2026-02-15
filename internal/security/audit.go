package security

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// AuditEvent represents a security event
type AuditEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	EventType  string    `json:"event_type"`
	IP         string    `json:"ip"`
	TunnelUUID string    `json:"tunnel_uuid,omitempty"`
	Details    string    `json:"details"`
	Severity   string    `json:"severity"` // info, warning, critical
}

// AuditLogger handles security audit logging
type AuditLogger struct {
	mu   sync.RWMutex
	file *os.File
	enc  *json.Encoder
}

var (
	instance *AuditLogger
	once     sync.Once
)

// GetAuditLogger returns singleton audit logger
func GetAuditLogger() (*AuditLogger, error) {
	var err error
	once.Do(func() {
		instance, err = newAuditLogger()
	})
	return instance, err
}

func newAuditLogger() (*AuditLogger, error) {
	dir, err := getAuditLogDir()
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	filename := filepath.Join(dir, fmt.Sprintf("audit-%s.log", time.Now().Format("2006-01-02")))
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	return &AuditLogger{
		file: file,
		enc:  json.NewEncoder(file),
	}, nil
}

func getAuditLogDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	switch runtime.GOOS {
	case "windows":
		return filepath.Join(home, "AppData", "Local", "ssrok", "audit"), nil
	case "darwin":
		return filepath.Join(home, "Library", "Logs", "ssrok", "audit"), nil
	default:
		return filepath.Join(home, ".local", "share", "ssrok", "audit"), nil
	}
}

// Log records an audit event
func (al *AuditLogger) Log(event AuditEvent) {
	al.mu.Lock()
	defer al.mu.Unlock()

	event.Timestamp = time.Now()
	al.enc.Encode(event)
}

// LogAuthFailure logs authentication failure
func (al *AuditLogger) LogAuthFailure(ip, tunnelUUID, reason string) {
	al.Log(AuditEvent{
		EventType:  "auth_failure",
		IP:         ip,
		TunnelUUID: tunnelUUID,
		Details:    reason,
		Severity:   "warning",
	})
}

// LogAuthSuccess logs successful authentication
func (al *AuditLogger) LogAuthSuccess(ip, tunnelUUID string) {
	al.Log(AuditEvent{
		EventType:  "auth_success",
		IP:         ip,
		TunnelUUID: tunnelUUID,
		Details:    "Authentication successful",
		Severity:   "info",
	})
}

// LogRateLimit logs rate limit hit
func (al *AuditLogger) LogRateLimit(ip, tunnelUUID string) {
	al.Log(AuditEvent{
		EventType:  "rate_limit",
		IP:         ip,
		TunnelUUID: tunnelUUID,
		Details:    "Rate limit exceeded",
		Severity:   "warning",
	})
}

// LogBruteForce logs brute force attempt
func (al *AuditLogger) LogBruteForce(ip, tunnelUUID string, attempts int) {
	al.Log(AuditEvent{
		EventType:  "brute_force",
		IP:         ip,
		TunnelUUID: tunnelUUID,
		Details:    fmt.Sprintf("Multiple failed attempts: %d", attempts),
		Severity:   "critical",
	})
}

// LogConnectionLimit logs connection limit hit
func (al *AuditLogger) LogConnectionLimit(ip string) {
	al.Log(AuditEvent{
		EventType: "connection_limit",
		IP:        ip,
		Details:   "Connection limit exceeded",
		Severity:  "warning",
	})
}

// Close closes the audit log
func (al *AuditLogger) Close() error {
	al.mu.Lock()
	defer al.mu.Unlock()
	if al.file != nil {
		return al.file.Close()
	}
	return nil
}
