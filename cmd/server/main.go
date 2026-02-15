package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
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
	serverUseTLS   bool
	templates      map[string]*template.Template
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

func loadTemplates() (map[string]*template.Template, error) {
	tmpls := make(map[string]*template.Template)

	layoutContent, err := ui.Templates.ReadFile("layout.html")
	if err != nil {
		return nil, err
	}

	// Parse layout as the base template
	baseTmpl, err := template.New("layout").Parse(string(layoutContent))
	if err != nil {
		return nil, err
	}

	// Define pages to load
	pages := []string{"login.html", "ratelimit.html", "notfound.html"}

	for _, page := range pages {
		pageContent, err := ui.Templates.ReadFile(page)
		if err != nil {
			return nil, err
		}

		// Clone the base template for this page
		pageTmpl, err := baseTmpl.Clone()
		if err != nil {
			return nil, err
		}

		// Parse the page content into the clone
		// This defines the "content" template specific to this page
		_, err = pageTmpl.Parse(string(pageContent))
		if err != nil {
			return nil, err
		}

		tmpls[page] = pageTmpl
	}

	return tmpls, nil
}

type gzipResponseWriter struct {
	http.ResponseWriter
	*gzip.Writer
}

func (w *gzipResponseWriter) Header() http.Header {
	return w.ResponseWriter.Header()
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

func gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}

		gz := gzip.NewWriter(w)
		defer gz.Close()

		w.Header().Set("Content-Encoding", "gzip")
		next.ServeHTTP(&gzipResponseWriter{ResponseWriter: w, Writer: gz}, r)
	})
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

	handler := mux

	port := utils.GetEnv("PORT", constants.DefaultPort)
	certFile := utils.GetEnv("SSROK_CERT_FILE", "certs/server.crt")
	keyFile := utils.GetEnv("SSROK_KEY_FILE", "certs/server.key")

	log.Printf("🚀 ssrok server starting on :%s", port)

	// TLS Configuration
	enableTLS := strings.ToLower(utils.GetEnv("SSROK_ENABLE_TLS", "false")) == "true"
	useTLS := false

	if enableTLS {
		if _, err := os.Stat(certFile); err == nil {
			if _, err := os.Stat(keyFile); err == nil {
				useTLS = true
			}
		}

		if !useTLS {
			log.Printf("Warning: SSROK_ENABLE_TLS is true but certs not found at %s", certFile)
		}
	}
	serverUseTLS = useTLS

	var server *http.Server

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	if useTLS {
		log.Printf("🔒 HTTPS enabled (HTTP/2)")
		server = &http.Server{
			Addr:    ":" + port,
			Handler: handler,
		}
		go func() {
			if err := server.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTPS server error: %v", err)
			}
		}()
	} else {
		log.Printf("🌐 HTTP mode (HTTP/2)")
		server = &http.Server{
			Addr:    ":" + port,
			Handler: handler,
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
		UseTLS:       req.UseTLS,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(constants.SessionDuration),
		RequestCount: make(map[string]int),
		LastRequest:  make(map[string]time.Time),
	}

	store.Save(sess)

	// Use server's actual TLS setting, not request's
	scheme := "http"
	if serverUseTLS {
		scheme = "https"
	}

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

	t := tunnel.NewTunnel(tunnelUUID, conn, sess.Port, sess.UseTLS)

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

	// Clean up session from store to free memory immediately
	store.Delete(tunnelUUID)

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

	// Try to get tunnelUUID from path first
	tunnelUUID := parts[0]

	// Check if the first part is a valid UUID
	isPathUUID := security.ValidateUUID(tunnelUUID)

	var sess *session.Session
	var ok bool

	// Check for session cookie to support asset loading (e.g. /_next/...)
	cookie, err := r.Cookie(constants.SessionCookieName)
	var cookieUUID string
	var cookieTokenHash string

	if err == nil {
		vals := strings.Split(cookie.Value, ":")
		if len(vals) == 2 {
			cookieUUID = vals[0]
			cookieTokenHash = vals[1]
		}
	}

	// Logic to determine target tunnel
	if isPathUUID {
		// Path explicitly requests a tunnel
		sess, ok = store.Get(tunnelUUID)
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			templates["notfound.html"].Execute(w, map[string]interface{}{
				"Title": "Tunnel Not Found",
			})
			return
		}
	} else if cookieUUID != "" {
		// Path is not a UUID (e.g. asset), try to find tunnel from cookie
		sess, ok = store.Get(cookieUUID)
		if ok && sess.TokenHash == cookieTokenHash {
			tunnelUUID = cookieUUID
		}
	}

	if sess == nil {
		if !isPathUUID {
			w.WriteHeader(http.StatusNotFound)
			templates["notfound.html"].Execute(w, map[string]interface{}{
				"Title": "Not Found",
			})
			return
		}
	}

	if !sess.CheckRateLimit(clientIP) {
		if auditLogger != nil {
			auditLogger.LogRateLimit(clientIP, tunnelUUID)
		}
		log.Printf("⛔ Rate limit exceeded: %s", clientIP)
		w.WriteHeader(http.StatusTooManyRequests)
		templates["ratelimit.html"].Execute(w, map[string]interface{}{
			"Title": constants.MsgRateLimitExceeded,
		})
		return
	}

	// Token validation
	token := r.URL.Query().Get("token")

	// If token in query is valid, set global cookie
	if token != "" && sess.VerifyToken(token) {
		log.Printf("✅ User logged in (Token): %s", clientIP)
		bruteProtector.RecordSuccess(clientIP)
		http.SetCookie(w, &http.Cookie{
			Name:     constants.SessionCookieName,
			Value:    fmt.Sprintf("%s:%s", tunnelUUID, sess.TokenHash),
			Path:     "/", // Global path to support assets
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

	// Verify Auth
	var authenticated bool

	// 1. Cookie Auth
	if cookieUUID == tunnelUUID && cookieTokenHash == sess.TokenHash {
		authenticated = true
	}

	// 2. Password Auth logic
	if sess.HasPassword() && !authenticated {
		if r.Method == http.MethodPost {
			password := r.FormValue("password")
			if sess.VerifyPassword(password) {
				log.Printf("✅ User logged in (Password): %s", clientIP)
				bruteProtector.RecordSuccess(clientIP)
				if auditLogger != nil {
					auditLogger.LogAuthSuccess(clientIP, tunnelUUID)
				}
				http.SetCookie(w, &http.Cookie{
					Name:     constants.SessionCookieName,
					Value:    fmt.Sprintf("%s:%s", tunnelUUID, sess.TokenHash),
					Path:     "/",
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
			templates["login.html"].Execute(w, map[string]interface{}{
				"Title": "Login",
				"Error": "Invalid password",
			})
			return
		}

		// Show login if not POST
		templates["login.html"].Execute(w, map[string]interface{}{
			"Title": "Login",
		})
		return
	} else if !authenticated {
		// No password but invalid token/cookie
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
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

	// Calculate target path for the proxy
	var targetPath string
	if isPathUUID {
		targetPath = "/" + strings.Join(parts[1:], "/")
	} else {
		targetPath = r.URL.Path
	}

	proxyRequest(t, w, r, targetPath)
}

func proxyRequest(t *tunnel.Tunnel, w http.ResponseWriter, r *http.Request, path string) {
	log.Printf("👤 User connected: %s -> %s %s", security.GetClientIP(r), r.Method, path)
	stream, err := t.Session.OpenStream()
	if err != nil {
		log.Printf("Proxy: failed to open stream: %v", err)
		http.Error(w, "Failed to open tunnel stream", http.StatusServiceUnavailable)
		return
	}
	defer stream.Close()

	if path == "" {
		path = "/"
	}
	if r.URL.RawQuery != "" {
		path += "?" + r.URL.RawQuery
	}

	reqLine := fmt.Sprintf("%s %s HTTP/1.1\r\n", r.Method, path)

	var buf bytes.Buffer
	buf.WriteString(reqLine)

	// Copy headers, excluding hop-by-hop headers
	hopByHop := map[string]bool{
		"Connection":          true,
		"Keep-Alive":          true,
		"Proxy-Authenticate":  true,
		"Proxy-Authorization": true,
		"Te":                  true,
		"Trailers":            true,
		"Transfer-Encoding":   true,
		"Upgrade":             true,
	}

	for key, values := range r.Header {
		if !hopByHop[key] {
			for _, value := range values {
				buf.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
			}
		}
	}

	buf.WriteString(fmt.Sprintf("Host: localhost:%d\r\n", t.LocalPort))
	buf.WriteString(fmt.Sprintf("X-Forwarded-For: %s\r\n", security.GetClientIP(r)))
	buf.WriteString(fmt.Sprintf("X-Forwarded-Host: %s\r\n", r.Host))
	buf.WriteString(fmt.Sprintf("X-Forwarded-Proto: %s\r\n", getScheme(r)))

	if r.ContentLength > 0 {
		buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", r.ContentLength))
	}

	buf.WriteString("\r\n")

	if _, err := stream.Write(buf.Bytes()); err != nil {
		http.Error(w, "Failed to write request", http.StatusServiceUnavailable)
		return
	}

	if r.Body != nil {
		reqBuf := tunnel.GetBuffer()
		io.CopyBuffer(stream, r.Body, reqBuf)
		tunnel.PutBuffer(reqBuf)
		r.Body.Close()
	}

	resp, err := http.ReadResponse(bufio.NewReader(stream), r)
	if err != nil {
		log.Printf("Proxy: Failed to read response from tunnel: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		if !hopByHop[key] {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Stream the body
	copyBuf := tunnel.GetBuffer()
	defer tunnel.PutBuffer(copyBuf)
	io.CopyBuffer(w, resp.Body, copyBuf)
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
