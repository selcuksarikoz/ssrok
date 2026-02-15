package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"ssrok/internal/constants"
	"ssrok/internal/protocol"
	"ssrok/internal/security"
	"ssrok/internal/session"
	"ssrok/internal/tunnel"
	"ssrok/internal/ui"
	"ssrok/internal/utils"
)

var (
	store          *session.Store
	tunnels        = make(map[string]*tunnel.Tunnel)
	tunnelMu       = &sync.RWMutex{}
	host           string
	templates      *template.Template
	connLimiter    *security.ConnectionLimiter
	bruteProtector *security.BruteForceProtector
	auditLogger    *security.AuditLogger
)

func init() {
	store = session.NewStore()
	connLimiter = security.NewConnectionLimiter(constants.MaxConnectionsPerIP)
	bruteProtector = security.NewBruteForceProtector(constants.MaxAuthAttempts, constants.BlockDuration)

	var err error
	auditLogger, err = security.GetAuditLogger()
	if err != nil {
		log.Printf("Warning: Failed to initialize audit logger: %v", err)
	}
}

func loadTemplates() (*template.Template, error) {
	tmpl := template.New("")

	layoutContent, err := ui.Templates.ReadFile("layout.html")
	if err != nil {
		return nil, err
	}

	loginContent, err := ui.Templates.ReadFile("login.html")
	if err != nil {
		return nil, err
	}

	ratelimitContent, err := ui.Templates.ReadFile("ratelimit.html")
	if err != nil {
		return nil, err
	}

	tmpl, err = tmpl.Parse(string(layoutContent))
	if err != nil {
		return nil, err
	}

	tmpl, err = tmpl.Parse(string(loginContent))
	if err != nil {
		return nil, err
	}

	tmpl, err = tmpl.Parse(string(ratelimitContent))
	if err != nil {
		return nil, err
	}

	return tmpl, nil
}

func main() {
	var err error
	templates, err = loadTemplates()
	if err != nil {
		log.Fatalf("Failed to load templates: %v", err)
	}

	host = utils.GetEnv("SSROK_HOST", constants.DefaultHost)
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")

	mux := http.NewServeMux()
	mux.HandleFunc(constants.EndpointRegister, handleRegister)
	mux.HandleFunc(constants.EndpointWebSocket, handleWebSocket)
	mux.HandleFunc(constants.EndpointRoot, handleTunnel)

	port := utils.GetEnv("PORT", constants.DefaultPort)
	certFile := utils.GetEnv("SSROK_CERT_FILE", "certs/server.crt")
	keyFile := utils.GetEnv("SSROK_KEY_FILE", "certs/server.key")

	log.Printf("🚀 ssrok server starting on :%s", port)

	// Check if TLS is configured
	useTLS := false
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			useTLS = true
		}
	}

	var server *http.Server

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	if useTLS {
		log.Printf("🔒 HTTPS enabled, cert: %s, key: %s", certFile, keyFile)
		server = &http.Server{
			Addr:    ":" + port,
			Handler: mux,
		}
		go func() {
			if err := server.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTPS server error: %v", err)
			}
		}()
	} else {
		log.Printf("🌐 HTTP mode")
		server = &http.Server{
			Addr:    ":" + port,
			Handler: mux,
		}
		go func() {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTP server error: %v", err)
			}
		}()
	}

	<-sigChan
	log.Println("🛑 Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	cleanup()
	log.Println("✅ Server stopped")
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, constants.MsgMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	// Limit body size
	r.Body = http.MaxBytesReader(w, r.Body, 1024) // 1KB max for register

	var req protocol.ConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, constants.MsgInvalidJSON, http.StatusBadRequest)
		return
	}

	if req.Port < constants.MinPort || req.Port > constants.MaxPort {
		http.Error(w, constants.MsgInvalidPort, http.StatusBadRequest)
		return
	}

	if req.RateLimit < 0 {
		req.RateLimit = constants.DefaultRateLimit
	}

	tunnelUUID := uuid.New().String()
	token := uuid.New().String()

	sess := &session.Session{
		UUID:         tunnelUUID,
		Port:         req.Port,
		PasswordHash: session.Hash(req.Password),
		TokenHash:    session.Hash(token),
		RateLimit:    req.RateLimit,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(constants.SessionDuration),
		RequestCount: make(map[string]int),
		LastRequest:  make(map[string]time.Time),
	}

	store.Save(sess)

	// Detect scheme from request or X-Forwarded-Proto header
	scheme := getScheme(r)

	// Build URL with detected scheme
	var tunnelURL string
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		tunnelURL = fmt.Sprintf("%s/%s", host, tunnelUUID)
	} else {
		tunnelURL = fmt.Sprintf("%s://%s/%s", scheme, host, tunnelUUID)
	}

	resp := protocol.ConfigResponse{
		UUID:      tunnelUUID,
		URL:       tunnelURL,
		Token:     token,
		ExpiresIn: constants.SessionDuration,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)

	log.Printf("✅ New tunnel registered: %s (expires in 1 hour)", tunnelUUID)
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	clientIP := security.GetClientIP(r)

	// Connection limit check
	if !connLimiter.TryConnect(clientIP) {
		if auditLogger != nil {
			auditLogger.LogConnectionLimit(clientIP)
		}
		http.Error(w, "Connection limit exceeded", http.StatusTooManyRequests)
		return
	}
	defer connLimiter.Disconnect(clientIP)

	path := strings.TrimPrefix(r.URL.Path, "/ws/")
	parts := strings.Split(path, "/")
	if len(parts) < 1 {
		http.Error(w, "Invalid tunnel ID", http.StatusBadRequest)
		return
	}

	tunnelUUID := parts[0]

	// Validate UUID format
	if !security.ValidateUUID(tunnelUUID) {
		http.Error(w, "Invalid tunnel ID format", http.StatusBadRequest)
		return
	}

	sess, ok := store.Get(tunnelUUID)
	if !ok {
		http.Error(w, constants.MsgTunnelNotFound, http.StatusNotFound)
		return
	}

	// Token validation required for all connections
	token := r.URL.Query().Get("token")
	if token == "" || !sess.VerifyToken(token) {
		if auditLogger != nil {
			auditLogger.LogAuthFailure(clientIP, tunnelUUID, "Invalid or missing token")
		}
		http.Error(w, "Unauthorized: invalid or missing token", http.StatusUnauthorized)
		return
	}

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	sess.Conn = conn
	sess.TunnelActive = true

	t := tunnel.NewTunnel(tunnelUUID, conn, sess.Port)

	tunnelMu.Lock()
	tunnels[tunnelUUID] = t
	tunnelMu.Unlock()

	log.Printf("🔌 Tunnel connected: %s -> localhost:%d", tunnelUUID, sess.Port)

	if err := t.HandleWebSocket(); err != nil {
		log.Printf("Tunnel error: %v", err)
	}

	t.Close()
	tunnelMu.Lock()
	delete(tunnels, tunnelUUID)
	tunnelMu.Unlock()

	sess.Conn = nil
	sess.TunnelActive = false

	log.Printf("🔌 Tunnel disconnected: %s", tunnelUUID)
}

func handleTunnel(w http.ResponseWriter, r *http.Request) {
	clientIP := security.GetClientIP(r)

	// Brute force check
	if !bruteProtector.Check(clientIP) {
		if auditLogger != nil {
			auditLogger.LogBruteForce(clientIP, "", constants.MaxAuthAttempts)
		}
		http.Error(w, "Too many failed attempts. Try again later.", http.StatusTooManyRequests)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/")
	path = strings.TrimSuffix(path, "/")

	parts := strings.Split(path, "/")
	if len(parts) < 1 || parts[0] == "" {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	tunnelUUID := parts[0]

	// Validate UUID format
	if !security.ValidateUUID(tunnelUUID) {
		http.Error(w, "Invalid tunnel ID format", http.StatusBadRequest)
		return
	}

	sess, ok := store.Get(tunnelUUID)
	if !ok {
		http.Error(w, "Tunnel not found or expired", http.StatusNotFound)
		return
	}

	if !sess.CheckRateLimit(clientIP) {
		if auditLogger != nil {
			auditLogger.LogRateLimit(clientIP, tunnelUUID)
		}
		w.WriteHeader(http.StatusTooManyRequests)
		templates.ExecuteTemplate(w, "ratelimit.html", map[string]interface{}{
			"Title": constants.MsgRateLimitExceeded,
		})
		return
	}

	// Token validation required for all requests (with or without password)
	token := r.URL.Query().Get("token")
	cookie, err := r.Cookie(constants.SessionCookieName)

	// If token in query is valid, set cookie
	if token != "" && sess.VerifyToken(token) {
		bruteProtector.RecordSuccess(clientIP)
		http.SetCookie(w, &http.Cookie{
			Name:     constants.SessionCookieName,
			Value:    sess.TokenHash,
			Path:     "/" + tunnelUUID,
			MaxAge:   constants.SessionCookieMaxAge,
			HttpOnly: true,
			Secure:   true,
			SameSite: constants.SessionCookieSameSite,
		})

		cleanURL := "/" + tunnelUUID
		if len(parts) > 1 {
			cleanURL += "/" + strings.Join(parts[1:], "/")
		}
		http.Redirect(w, r, cleanURL, http.StatusFound)
		return
	}

	// Check if token exists in cookie
	tokenValid := err == nil && cookie.Value == sess.TokenHash

	// If password is set, show login page
	if sess.HasPassword() {
		if !tokenValid {
			if r.Method == http.MethodPost {
				password := r.FormValue("password")
				if sess.VerifyPassword(password) {
					bruteProtector.RecordSuccess(clientIP)
					if auditLogger != nil {
						auditLogger.LogAuthSuccess(clientIP, tunnelUUID)
					}
					http.SetCookie(w, &http.Cookie{
						Name:     constants.SessionCookieName,
						Value:    sess.TokenHash,
						Path:     "/" + tunnelUUID,
						MaxAge:   constants.SessionCookieMaxAge,
						HttpOnly: true,
						Secure:   true,
						SameSite: constants.SessionCookieSameSite,
					})
					http.Redirect(w, r, r.URL.Path, http.StatusFound)
					return
				}
				bruteProtector.RecordFailure(clientIP)
				if auditLogger != nil {
					auditLogger.LogAuthFailure(clientIP, tunnelUUID, "Invalid password")
				}
				w.WriteHeader(http.StatusUnauthorized)
				templates.ExecuteTemplate(w, "login.html", map[string]interface{}{
					"Title": "Login",
					"Error": "Invalid password",
				})
				return
			}
			templates.ExecuteTemplate(w, "login.html", map[string]interface{}{
				"Title": "Login",
			})
			return
		}
	} else {
		// No password but invalid token = unauthorized
		if !tokenValid {
			bruteProtector.RecordFailure(clientIP)
			if auditLogger != nil {
				auditLogger.LogAuthFailure(clientIP, tunnelUUID, "Invalid or missing token")
			}
			http.Error(w, "Unauthorized: valid token required", http.StatusUnauthorized)
			return
		}
	}

	if !sess.TunnelActive || sess.Conn == nil {
		http.Error(w, constants.MsgTunnelNotActive, http.StatusServiceUnavailable)
		return
	}

	tunnelMu.RLock()
	t, ok := tunnels[tunnelUUID]
	tunnelMu.RUnlock()

	if !ok {
		http.Error(w, constants.MsgTunnelNotActive, http.StatusServiceUnavailable)
		return
	}

	proxyRequest(t, w, r, path)
}

func proxyRequest(t *tunnel.Tunnel, w http.ResponseWriter, r *http.Request, path string) {
	stream, err := t.Session.OpenStream()
	if err != nil {
		http.Error(w, "Failed to open tunnel stream", http.StatusServiceUnavailable)
		return
	}
	defer stream.Close()

	targetURL := "/" + strings.Join(strings.Split(path, "/")[1:], "/")
	if targetURL == "" {
		targetURL = "/"
	}
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	reqLine := fmt.Sprintf("%s %s HTTP/1.1\r\n", r.Method, targetURL)

	var buf bytes.Buffer
	buf.WriteString(reqLine)

	for key, values := range r.Header {
		for _, value := range values {
			buf.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
		}
	}

	buf.WriteString(fmt.Sprintf("X-Forwarded-For: %s\r\n", security.GetClientIP(r)))
	buf.WriteString(fmt.Sprintf("X-Forwarded-Host: %s\r\n", r.Host))
	buf.WriteString(fmt.Sprintf("X-Forwarded-Proto: %s\r\n", getScheme(r)))

	buf.WriteString("\r\n")

	if _, err := stream.Write(buf.Bytes()); err != nil {
		http.Error(w, "Failed to write request", http.StatusServiceUnavailable)
		return
	}

	if r.Body != nil {
		buf := tunnel.GetBuffer()
		io.CopyBuffer(stream, r.Body, buf)
		tunnel.PutBuffer(buf)
		r.Body.Close()
	}

	respBuf := tunnel.GetBuffer()
	defer tunnel.PutBuffer(respBuf)
	n, err := stream.Read(respBuf)
	if err != nil && err != io.EOF {
		http.Error(w, "Failed to read response", http.StatusServiceUnavailable)
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(respBuf[:n])), r)
	if err != nil {
		w.Write(respBuf[:n])
		buf := tunnel.GetBuffer()
		io.CopyBuffer(w, stream, buf)
		tunnel.PutBuffer(buf)
		return
	}

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)

	io.Copy(w, resp.Body)
	resp.Body.Close()
}

func getScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if scheme := r.Header.Get("X-Forwarded-Proto"); scheme != "" {
		return scheme
	}
	return "http"
}

func cleanup() {
	tunnelMu.Lock()
	defer tunnelMu.Unlock()

	for uuid, t := range tunnels {
		log.Printf("Closing tunnel: %s", uuid)
		t.Close()
	}
}
