package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"ssrok/internal/constants"
	"ssrok/internal/logger"
	"ssrok/internal/types"
	"ssrok/internal/ui"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
	ReadBufferSize:  constants.DashboardWSReadBuffer,
	WriteBufferSize: constants.DashboardWSWriteBuffer,
}

type Dashboard struct {
	mu             sync.RWMutex
	logs           []types.HTTPLog
	maxLogs        int
	clients        map[*websocket.Conn]bool
	clientsMu      sync.RWMutex
	server         *http.Server
	port           int
	publicURL      string
	logger         *logger.Logger
	logPath        string
	securityEvents []types.SecurityEvent
	active         int64 // active tunnel connections
}

func New(port int, publicURL string, log *logger.Logger, logPath string) *Dashboard {
	return &Dashboard{
		maxLogs:        constants.DashboardMaxLogs,
		clients:        make(map[*websocket.Conn]bool),
		port:           port,
		publicURL:      publicURL,
		logger:         log,
		logPath:        logPath,
		securityEvents: make([]types.SecurityEvent, 0),
	}
}

func (d *Dashboard) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", d.handleIndex)
	mux.HandleFunc("/ws", d.handleWebSocket)
	mux.HandleFunc("/api/logs", d.handleLogs)
	mux.HandleFunc("/api/stats", d.handleStats)
	mux.HandleFunc("/api/security", d.handleSecurityEvents)
	mux.HandleFunc("/public-url", d.handlePublicURL)

	d.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", d.port),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		if err := d.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Dashboard server error: %v", err)
		}
	}()

	return nil
}

func (d *Dashboard) Stop() error {
	if d.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), constants.DashboardShutdownTimeout)
		defer cancel()
		return d.server.Shutdown(ctx)
	}
	return nil
}

func (d *Dashboard) AddLog(logEntry types.HTTPLog) {
	d.mu.Lock()
	d.logs = append(d.logs, logEntry)
	if len(d.logs) > d.maxLogs {
		d.logs = d.logs[len(d.logs)-d.maxLogs:]
	}
	d.mu.Unlock()

	go d.broadcastLog(logEntry)
}

func (d *Dashboard) AddSecurityEvent(event types.SecurityEvent) {
	d.mu.Lock()
	d.securityEvents = append(d.securityEvents, event)
	if len(d.securityEvents) > d.maxLogs {
		d.securityEvents = d.securityEvents[len(d.securityEvents)-d.maxLogs:]
	}
	d.mu.Unlock()

	go d.broadcastSecurityEvent(event)
}

func (d *Dashboard) broadcastSecurityEvent(event types.SecurityEvent) {
	d.clientsMu.RLock()
	defer d.clientsMu.RUnlock()

	data, err := json.Marshal(map[string]interface{}{"type": "security", "data": event})
	if err != nil {
		return
	}

	for client := range d.clients {
		if err := client.WriteMessage(websocket.TextMessage, data); err != nil {
			client.Close()
			delete(d.clients, client)
		}
	}
}

func (d *Dashboard) broadcastLog(logEntry types.HTTPLog) {
	d.clientsMu.RLock()
	defer d.clientsMu.RUnlock()

	data, err := json.Marshal(logEntry)
	if err != nil {
		return
	}

	for client := range d.clients {
		if err := client.WriteMessage(websocket.TextMessage, data); err != nil {
			client.Close()
			delete(d.clients, client)
		}
	}
}

func (d *Dashboard) handleIndex(w http.ResponseWriter, r *http.Request) {
	layoutContent, err := ui.Templates.ReadFile("layout.html")
	if err != nil {
		http.Error(w, "Layout not found", http.StatusInternalServerError)
		return
	}

	dashboardContent, err := ui.Templates.ReadFile("dashboard.html")
	if err != nil {
		http.Error(w, "Dashboard not found", http.StatusInternalServerError)
		return
	}

	t, err := template.New("layout").Parse(string(layoutContent))
	if err != nil {
		http.Error(w, "Template parse error", http.StatusInternalServerError)
		return
	}

	_, err = t.Parse(string(dashboardContent))
	if err != nil {
		http.Error(w, "Dashboard parse error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	if err := t.Execute(w, map[string]string{"Title": "ssrok Dashboard"}); err != nil {
		log.Printf("Error rendering dashboard: %v", err)
	}
}

func (d *Dashboard) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	d.clientsMu.Lock()
	d.clients[conn] = true
	d.clientsMu.Unlock()

	defer func() {
		d.clientsMu.Lock()
		delete(d.clients, conn)
		d.clientsMu.Unlock()
	}()

	d.mu.RLock()
	logs := make([]types.HTTPLog, len(d.logs))
	copy(logs, d.logs)
	d.mu.RUnlock()

	for _, logEntry := range logs {
		data, _ := json.Marshal(logEntry)
		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
			return
		}
	}

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func (d *Dashboard) handleLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	d.mu.RLock()
	logs := make([]types.HTTPLog, len(d.logs))
	copy(logs, d.logs)
	d.mu.RUnlock()
	json.NewEncoder(w).Encode(logs)
}

func (d *Dashboard) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	d.mu.RLock()
	totalRequests := len(d.logs)
	d.mu.RUnlock()

	d.clientsMu.RLock()
	clientsCount := len(d.clients)
	d.clientsMu.RUnlock()

	activeVal := atomic.LoadInt64(&d.active)

	stats := map[string]interface{}{
		"total_requests":    totalRequests,
		"active_requests":   activeVal,
		"dashboard_clients": clientsCount,
		"public_url":        d.publicURL,
		"log_path":          d.logPath,
	}
	json.NewEncoder(w).Encode(stats)
}

func (d *Dashboard) IncActive() {
	atomic.AddInt64(&d.active, 1)
}

func (d *Dashboard) DecActive() {
	atomic.AddInt64(&d.active, -1)
}

func (d *Dashboard) handlePublicURL(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"public_url": d.publicURL,
	})
}

func (d *Dashboard) handleSecurityEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	d.mu.RLock()
	events := make([]types.SecurityEvent, len(d.securityEvents))
	copy(events, d.securityEvents)
	d.mu.RUnlock()
	json.NewEncoder(w).Encode(events)
}

func (d *Dashboard) GetLogPath() string {
	return d.logPath
}

func (d *Dashboard) GetURL() string {
	return fmt.Sprintf("http://localhost:%d", d.port)
}
