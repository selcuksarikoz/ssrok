package security

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"ssrok/internal/constants"
)

type AuditEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	EventType  string    `json:"event_type"`
	IP         string    `json:"ip"`
	TunnelUUID string    `json:"tunnel_uuid,omitempty"`
	Details    string    `json:"details"`
	Severity   string    `json:"severity"`
}

type AuditLogger struct {
	mu          sync.RWMutex
	file        *os.File
	enc         *json.Encoder
	logCount    map[string]int
	windowStart time.Time
}

var (
	instance *AuditLogger
	once     sync.Once
)

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
		file:        file,
		enc:         json.NewEncoder(file),
		logCount:    make(map[string]int),
		windowStart: time.Now(),
	}, nil
}

func getAuditLogDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	switch runtime.GOOS {
	case "windows":
		return filepath.Join(home, "AppData", "Local", constants.AppName, "audit"), nil
	case "darwin":
		return filepath.Join(home, "Library", "Logs", constants.AppName, "audit"), nil
	default:
		return filepath.Join(home, ".local", "share", constants.AppName, "audit"), nil
	}
}

func (al *AuditLogger) Log(event AuditEvent) {
	al.mu.Lock()
	defer al.mu.Unlock()

	now := time.Now()

	if now.Sub(al.windowStart) > time.Minute {
		al.windowStart = now
		al.logCount = make(map[string]int)
	}

	totalLogs := 0
	for _, count := range al.logCount {
		totalLogs += count
	}

	if totalLogs >= constants.MaxAuditLogsPerMinute {
		return
	}

	al.logCount[event.EventType]++
	event.Timestamp = now
	al.enc.Encode(event)
}

func (al *AuditLogger) LogAuthFailure(ip, tunnelUUID, reason string) {
	al.Log(AuditEvent{
		EventType:  "auth_failure",
		IP:         ip,
		TunnelUUID: tunnelUUID,
		Details:    reason,
		Severity:   "warning",
	})
}

func (al *AuditLogger) LogAuthSuccess(ip, tunnelUUID string) {
	al.Log(AuditEvent{
		EventType:  "auth_success",
		IP:         ip,
		TunnelUUID: tunnelUUID,
		Details:    "Authentication successful",
		Severity:   "info",
	})
}

func (al *AuditLogger) LogRateLimit(ip, tunnelUUID string) {
	al.Log(AuditEvent{
		EventType:  "rate_limit",
		IP:         ip,
		TunnelUUID: tunnelUUID,
		Details:    "Rate limit exceeded",
		Severity:   "warning",
	})
}

func (al *AuditLogger) LogBruteForce(ip, tunnelUUID string, attempts int) {
	al.Log(AuditEvent{
		EventType:  "brute_force",
		IP:         ip,
		TunnelUUID: tunnelUUID,
		Details:    fmt.Sprintf("Multiple failed attempts: %d", attempts),
		Severity:   "critical",
	})
}

func (al *AuditLogger) LogConnectionLimit(ip string) {
	al.Log(AuditEvent{
		EventType: "connection_limit",
		IP:        ip,
		Details:   "Connection limit exceeded",
		Severity:  "warning",
	})
}

func (al *AuditLogger) LogTunnelRegister(ip, tunnelUUID string, port int) {
	al.Log(AuditEvent{
		EventType:  "tunnel_register",
		IP:         ip,
		TunnelUUID: tunnelUUID,
		Details:    fmt.Sprintf("Tunnel registered for port %d", port),
		Severity:   "info",
	})
}

func (al *AuditLogger) LogTunnelConnect(ip, tunnelUUID string) {
	al.Log(AuditEvent{
		EventType:  "tunnel_connect",
		IP:         ip,
		TunnelUUID: tunnelUUID,
		Details:    "Client connected to tunnel via WebSocket",
		Severity:   "info",
	})
}

func (al *AuditLogger) LogTunnelDisconnect(ip, tunnelUUID, reason string) {
	al.Log(AuditEvent{
		EventType:  "tunnel_disconnect",
		IP:         ip,
		TunnelUUID: tunnelUUID,
		Details:    fmt.Sprintf("Tunnel disconnected: %s", reason),
		Severity:   "info",
	})
}

func (al *AuditLogger) LogProxyRequest(ip, tunnelUUID, method, path string, statusCode int, duration time.Duration) {
	al.Log(AuditEvent{
		EventType:  "proxy_request",
		IP:         ip,
		TunnelUUID: tunnelUUID,
		Details:    fmt.Sprintf("%s %s -> %d (%v)", method, path, statusCode, duration),
		Severity:   "info",
	})
}

func (al *AuditLogger) LogStreamingRequest(ip, tunnelUUID, method, path string, contentLength int64) {
	al.Log(AuditEvent{
		EventType:  "streaming_request",
		IP:         ip,
		TunnelUUID: tunnelUUID,
		Details:    fmt.Sprintf("%s %s (streaming, size: %d bytes)", method, path, contentLength),
		Severity:   "info",
	})
}

func (al *AuditLogger) LogRequestFlooding(ip, tunnelUUID string, requestCount int, window time.Duration) {
	al.Log(AuditEvent{
		EventType:  "request_flooding",
		IP:         ip,
		TunnelUUID: tunnelUUID,
		Details:    fmt.Sprintf("High request volume detected: %d requests in %v", requestCount, window),
		Severity:   "warning",
	})
}

func (al *AuditLogger) LogInvalidRequest(ip, tunnelUUID, path, reason string) {
	al.Log(AuditEvent{
		EventType:  "invalid_request",
		IP:         ip,
		TunnelUUID: tunnelUUID,
		Details:    fmt.Sprintf("Invalid request to %s: %s", path, reason),
		Severity:   "warning",
	})
}

func (al *AuditLogger) Close() error {
	al.mu.Lock()
	defer al.mu.Unlock()
	if al.file != nil {
		return al.file.Close()
	}
	return nil
}
