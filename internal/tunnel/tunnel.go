package tunnel

import (
	"fmt"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"

	"ssrok/internal/dashboard"
	"ssrok/internal/logger"
)

type Tunnel struct {
	UUID        string
	WSConn      *websocket.Conn
	Session     *yamux.Session
	LocalPort   int
	UseTLS      bool
	mu          sync.RWMutex
	isClosed    bool
	log         *logger.Logger
	localAddr   string
	LogCallback func(string)
	dashboard   *dashboard.Dashboard
	E2EE        bool

	// Stats
	BytesIn     int64 // atomic
	BytesOut    int64 // atomic
	TotalReqs   int64 // atomic
	ActiveConns int64 // atomic
}

// NewTunnel creates a new tunnel instance
func NewTunnel(uuid string, wsConn *websocket.Conn, localPort int, useTLS bool, e2ee bool) *Tunnel {
	return &Tunnel{
		UUID:      uuid,
		WSConn:    wsConn,
		LocalPort: localPort,
		UseTLS:    useTLS,
		E2EE:      e2ee,
		localAddr: fmt.Sprintf("localhost:%d", localPort),
	}
}

// Logger returns the tunnel logger
func (t *Tunnel) Logger() *logger.Logger {
	return t.log
}

// SetDashboard attaches a dashboard to the tunnel
func (t *Tunnel) SetDashboard(d *dashboard.Dashboard) {
	t.dashboard = d
}

// GetLogPath returns the path to the tunnel log file
func (t *Tunnel) GetLogPath() string {
	if t.log != nil {
		return t.log.GetLogPath()
	}
	return ""
}

// Close gracefully shuts down the tunnel and its connections
func (t *Tunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.isClosed {
		return nil
	}

	t.isClosed = true

	if t.log != nil {
		t.log.LogEvent("Tunnel closing", t.LocalPort)
	}

	if t.Session != nil {
		t.Session.Close()
	}

	if t.WSConn != nil {
		t.WSConn.Close()
	}

	if t.log != nil {
		t.log.LogEvent("Tunnel closed", t.LocalPort)
		t.log.Close()
	}

	return nil
}
