package main

import (
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
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"ssrok/internal/constants"
	"ssrok/internal/security"
	"ssrok/internal/session"
	"ssrok/internal/tunnel"
	"ssrok/internal/types"
	"ssrok/internal/ui"
	"ssrok/internal/utils"
)

var (
	store          session.StoreInterface
	tunnels        = make(map[string]*tunnel.Tunnel)
	tunnelMu       = &sync.RWMutex{}
	host           string
	serverPort     string
	serverUseTLS   bool
	templates      map[string]*template.Template
	connLimiter    *security.ConnectionLimiter
	bruteProtector *security.BruteForceProtector
	auditLogger    *security.AuditLogger
)

var hopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailers":            true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

var sensitiveRequestHeaders = map[string]bool{
	"Cookie": true,
}

var dangerousResponseHeaders = map[string]bool{
	"Set-Cookie":                true,
	"Strict-Transport-Security": true,
	"Content-Security-Policy":   true,
	"X-Frame-Options":           true,
	"X-Xss-Protection":          true,
	"X-Content-Type-Options":    true,
}

var hopByHopHeadersNames = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

func init() {
	var err error
	store, err = session.NewStore()
	if err != nil {
		log.Fatalf("Failed to initialize session store: %v", err)
	}
	store.OnExpire(func(uuid string) {
		tunnelMu.Lock()
		if t, ok := tunnels[uuid]; ok {
			t.Close()
			delete(tunnels, uuid)
			log.Printf("🗑 Tunnel closed (expired): %s", uuid)
		}
		tunnelMu.Unlock()
	})
	connLimiter = security.NewConnectionLimiter(constants.MaxConnectionsPerIP)
	bruteProtector = security.NewBruteForceProtector(constants.MaxAuthAttempts, constants.BlockDuration)

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

	baseTmpl, err := template.New("layout").Parse(string(layoutContent))
	if err != nil {
		return nil, err
	}

	pages := []string{"login.html", "ratelimit.html", "notfound.html", "home.html", "error.html", "disconnected.html"}

	for _, page := range pages {
		pageContent, err := ui.Templates.ReadFile(page)
		if err != nil {
			return nil, err
		}

		pageTmpl, err := baseTmpl.Clone()
		if err != nil {
			return nil, err
		}

		_, err = pageTmpl.Parse(string(pageContent))
		if err != nil {
			return nil, err
		}

		tmpls[page] = pageTmpl
	}

	return tmpls, nil
}

func renderTemplate(w http.ResponseWriter, name string, data map[string]interface{}) {
	tmpl, ok := templates[name]
	if !ok {
		// Fallback for missing template - prevents panic
		log.Printf("Error: Template %s not found", name)
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Error executing template %s: %v", name, err)
	}
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

func (w *gzipResponseWriter) Flush() {
	w.Writer.Flush()
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, Upgrade")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Upgrade")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") ||
			r.Header.Get("Upgrade") == "websocket" {
			next.ServeHTTP(w, r)
			return
		}

		// Skip gzip for tunnel proxy requests — upstream handles its own encoding
		path := strings.TrimPrefix(r.URL.Path, "/")
		parts := strings.SplitN(path, "/", 2)
		if len(parts) > 0 && len(parts[0]) == 36 {
			next.ServeHTTP(w, r)
			return
		}

		gz := tunnel.GetGzipWriter(w)
		defer tunnel.PutGzipWriter(gz)

		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Del("Content-Length")
		next.ServeHTTP(&gzipResponseWriter{ResponseWriter: w, Writer: gz}, r)
	})
}

func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("🔥 PANIC RECOVERED: %v\nStack Trace:\n%s", err, string(debug.Stack()))
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func main() {
	var err error
	templates, err = loadTemplates()
	if err != nil {
		log.Fatalf("Failed to load templates: %v", err)
	}

	host = utils.GetEnv("SSROK_SERVER", constants.DefaultHost)
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")

	// Strip port from host if present (we'll use serverPort separately)
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		host = host[:idx]
	}

	mux := http.NewServeMux()
	mux.HandleFunc(constants.EndpointRegister, handleRegister)
	mux.HandleFunc(constants.EndpointWebSocket, handleWebSocket)
	mux.HandleFunc(constants.EndpointRoot, handleTunnel)

	var handler http.Handler = mux
	handler = recoveryMiddleware(handler)
	handler = corsMiddleware(handler)
	handler = security.SecurityHeaders(handler)
	handler = gzipMiddleware(handler)

	serverPort = utils.GetEnv("PORT", constants.DefaultPort)
	certFile := utils.GetEnv("SSROK_CERT_FILE", "certs/server.crt")
	keyFile := utils.GetEnv("SSROK_KEY_FILE", "certs/server.key")

	log.Printf("🚀 ssrok server starting on :%s", serverPort)

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

	server = &http.Server{
		Addr:              ":" + serverPort,
		Handler:           handler,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	if useTLS {
		log.Printf("🔒 HTTPS enabled (HTTP/2)")
		go func() {
			if err := server.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
				log.Fatalf("HTTPS server error: %v", err)
			}
		}()
	} else {
		log.Printf("🌐 HTTP mode")
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

	r.Body = http.MaxBytesReader(w, r.Body, 1024)

	var req types.ConfigRequest
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

	sessionDuration := constants.SessionDuration
	if req.ExpiresIn > 0 {
		sessionDuration = req.ExpiresIn
		if sessionDuration < constants.MinSessionDuration {
			sessionDuration = constants.MinSessionDuration
		}
		if sessionDuration > constants.MaxSessionDuration {
			sessionDuration = constants.MaxSessionDuration
		}
	}

	tunnelUUID := uuid.New().String()
	token := uuid.New().String()

	passwordHash := utils.HashSHA256(req.Password)

	sess := &session.Session{
		UUID:         tunnelUUID,
		Port:         req.Port,
		PasswordHash: passwordHash,
		TokenHash:    utils.HashSHA256(token),
		RateLimit:    req.RateLimit,
		UseTLS:       req.UseTLS,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(sessionDuration),
		RequestCount: make(map[string]int),
		LastRequest:  make(map[string]time.Time),
	}

	log.Printf("🔔 Register: New tunnel created: %s", tunnelUUID)
	store.Save(sess)

	scheme := utils.GetScheme(r)
	log.Printf("🌐 Detected scheme: %s (TLS: %v, X-Forwarded-Proto: %s)", scheme, r.TLS != nil, r.Header.Get("X-Forwarded-Proto"))

	// Build host with port for URL
	urlHost := host
	if !isStandardPort(scheme, serverPort) {
		urlHost = host + ":" + serverPort
	}

	var tunnelURL string
	tunnelURL = utils.ConstructURL(scheme, urlHost, tunnelUUID)

	resp := types.ConfigResponse{
		UUID:      tunnelUUID,
		URL:       tunnelURL,
		Token:     token,
		ExpiresIn: sessionDuration,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)

	log.Printf("✅ New tunnel registered: %s (expires in %s)", tunnelUUID, sessionDuration)
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	clientIP := security.GetClientIP(r)

	log.Printf("🔌 WebSocket request received: %s from %s", r.URL.Path, r.Header.Get("Upgrade"))

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

	if !security.ValidateUUID(tunnelUUID) {
		http.Error(w, "Invalid tunnel ID format", http.StatusBadRequest)
		return
	}

	sess, ok := store.Get(tunnelUUID)
	if !ok {
		http.Error(w, constants.MsgTunnelNotFound, http.StatusNotFound)
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" || !sess.VerifyToken(token) {
		if auditLogger != nil {
			auditLogger.LogAuthFailure(clientIP, tunnelUUID, "Invalid or missing token")
		}
		http.Error(w, "Unauthorized: invalid or missing token", http.StatusUnauthorized)
		return
	}

	log.Printf("🔌 WebSocket: Upgrading connection for tunnel: %s", tunnelUUID)
	conn, err := websocket.Upgrade(w, r, nil, constants.WSBufferSize, constants.WSBufferSize)
	if err != nil {
		log.Printf("❌ WebSocket upgrade error: %v", err)
		return
	}

	sess.Conn = conn
	sess.TunnelActive = true

	log.Printf("🔔 WebSocket: Client connected, saving session: %s", tunnelUUID)
	store.Save(sess)

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

	store.Delete(tunnelUUID)

	log.Printf("🔌 Tunnel disconnected: %s", tunnelUUID)
}

func handleTunnel(w http.ResponseWriter, r *http.Request) {
	clientIP := security.GetClientIP(r)

	if !bruteProtector.Check(clientIP) {
		if auditLogger != nil {
			auditLogger.LogBruteForce(clientIP, "", constants.MaxAuthAttempts)
		}
		http.Error(w, "Too many failed attempts. Try again later.", http.StatusTooManyRequests)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/")
	path = strings.TrimSuffix(path, "/")

	if !security.ValidatePath(path) {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	parts := strings.Split(path, "/")
	if len(parts) < 1 || parts[0] == "" {
		renderTemplate(w, "home.html", map[string]interface{}{
			"Title": "ssrok - Secure Tunneling",
		})
		return
	}

	tunnelUUID := parts[0]
	isPathUUID := security.ValidateUUID(tunnelUUID)

	var sess *session.Session
	var ok bool

	cookie, err := r.Cookie(constants.SessionCookieName)
	var cookieUUID string

	if err == nil {
		cookieUUID, _ = session.VerifyCookieValue(cookie.Value)
	}

	if isPathUUID {
		sess, ok = store.Get(tunnelUUID)
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			renderTemplate(w, "notfound.html", map[string]interface{}{
				"Title": "Tunnel Not Found",
			})
			return
		}
	} else if cookieUUID != "" {
		sess, ok = store.Get(cookieUUID)
		if ok {
			tunnelUUID = cookieUUID
		}
	}

	if sess == nil {
		if !isPathUUID {
			w.WriteHeader(http.StatusNotFound)
			renderTemplate(w, "notfound.html", map[string]interface{}{
				"Title": "Not Found",
			})
			return
		}
	}

	if !sess.CheckRateLimit(clientIP) {
		store.Save(sess)

		if auditLogger != nil {
			auditLogger.LogRateLimit(clientIP, tunnelUUID)
		}

		tunnelMu.RLock()
		tLog, okLog := tunnels[tunnelUUID]
		tunnelMu.RUnlock()
		if okLog {
			tLog.SendLog(fmt.Sprintf("⛔ Rate limit exceeded: %s", clientIP))
		}

		log.Printf("⛔ Rate limit exceeded: %s", clientIP)
		w.WriteHeader(http.StatusTooManyRequests)
		renderTemplate(w, "ratelimit.html", map[string]interface{}{
			"Title": constants.MsgRateLimitExceeded,
		})
		return
	}
	// Save the session with the updated request count/timestamp
	store.Save(sess)

	var authenticated bool
	var extraPath string

	// Check for token in URL (Magic URL / API Key support)
	token := r.URL.Query().Get("token")
	originalToken := token

	// Support malformed URLs where path is appended to token (e.g. ?token=xyz/api/req)
	if token != "" && !sess.VerifyToken(token) {
		if idx := strings.IndexByte(token, '/'); idx >= 0 {
			attemptToken := token[:idx]
			if sess.VerifyToken(attemptToken) {
				token = attemptToken
				extraPath = originalToken[idx:] // Use originalToken to get the path
				log.Printf("🔹 Parsed malformed token. Token: %s, Path: %s", token, extraPath)
			}
		}
	} else if token != "" {
		// Normal token match
		// log.Printf("Token matched directly: %s", token)
	}

	if token != "" && sess.VerifyToken(token) {
		log.Printf("✅ User logged in (Token): %s", clientIP)

		// Fetch tunnel for logging (if active)
		tunnelMu.RLock()
		tLog, okLog := tunnels[tunnelUUID]
		tunnelMu.RUnlock()

		if okLog {
			tLog.SendLog(fmt.Sprintf("=> User connected via Magic URL: %s", clientIP))
		}

		bruteProtector.RecordSuccess(clientIP)
		http.SetCookie(w, &http.Cookie{
			Name:     constants.SessionCookieName,
			Value:    session.SignCookieValue(tunnelUUID),
			Path:     "/",
			MaxAge:   constants.SessionCookieMaxAge,
			HttpOnly: true,
			Secure:   true,
			SameSite: constants.SessionCookieSameSite,
		})

		// For API clients (curl/Postman): Do not redirect, just allow access.
		// Even 307 requires client support. Direct proxying is best.
		authenticated = true
	}

	if !authenticated && cookieUUID == tunnelUUID && cookieUUID != "" {
		sessFromCookie, ok := store.Get(cookieUUID)
		if ok && sessFromCookie != nil {
			authenticated = true
			sess = sessFromCookie
			store.Save(sess)
		}
	}

	if !authenticated {
		tunnelMu.RLock()
		tLog, okLog := tunnels[tunnelUUID]
		tunnelMu.RUnlock()

		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 4096)

			csrfToken := r.FormValue("csrf_token")
			if !session.VerifyCSRFToken(csrfToken) {
				if auditLogger != nil {
					auditLogger.LogAuthFailure(clientIP, tunnelUUID, "Invalid CSRF token")
				}
				http.Error(w, "Invalid request", http.StatusForbidden)
				return
			}

			password := r.FormValue("password")
			if sess.VerifyPassword(password) {
				log.Printf("✅ User logged in (Password): %s", clientIP)
				if okLog {
					tLog.SendLog("=> login is done")
					tLog.SendLog(fmt.Sprintf("=> User connected: %s", clientIP))
				}

				bruteProtector.RecordSuccess(clientIP)
				if auditLogger != nil {
					auditLogger.LogAuthSuccess(clientIP, tunnelUUID)
				}
				http.SetCookie(w, &http.Cookie{
					Name:     constants.SessionCookieName,
					Value:    session.SignCookieValue(tunnelUUID),
					Path:     "/",
					MaxAge:   constants.SessionCookieMaxAge,
					HttpOnly: true,
					Secure:   true,
					SameSite: constants.SessionCookieSameSite,
				})
				http.Redirect(w, r, r.URL.Path, http.StatusFound)
				return
			}
			if okLog {
				tLog.SendLog("=> password incorrect")
			}
			bruteProtector.RecordFailure(clientIP)
			if auditLogger != nil {
				auditLogger.LogAuthFailure(clientIP, tunnelUUID, "Invalid password")
			}
			csrf := session.SignCSRFToken(session.GenerateCSRFToken())
			w.WriteHeader(http.StatusUnauthorized)
			renderTemplate(w, "login.html", map[string]interface{}{
				"Title":     "Login",
				"Error":     "Invalid password",
				"CSRFToken": csrf,
			})
			return
		}

		if okLog {
			tLog.SendLog("=> login page opened")
		}
		csrf := session.SignCSRFToken(session.GenerateCSRFToken())
		renderTemplate(w, "login.html", map[string]interface{}{
			"Title":     "Login",
			"CSRFToken": csrf,
		})
		return
	}

	tunnelMu.RLock()
	t, tunnelExists := tunnels[tunnelUUID]
	tunnelMu.RUnlock()

	if !sess.TunnelActive || !tunnelExists {
		w.WriteHeader(http.StatusServiceUnavailable)
		renderTemplate(w, "disconnected.html", map[string]interface{}{
			"Title":     "Tunnel Disconnected",
			"Port":      sess.Port,
			"ExpiresIn": time.Until(sess.ExpiresAt).Round(time.Minute).String(),
		})
		return
	}

	var targetPath string
	if isPathUUID {
		// Robustly strip the /UUID prefix from the path
		targetPath = strings.TrimPrefix(r.URL.Path, "/"+tunnelUUID)
		if targetPath == "" {
			targetPath = "/"
		}
	} else {
		targetPath = r.URL.Path
	}

	// Redirect to /{UUID}/... if user accessed via cookie fallback (e.g. localhost/dashboard -> localhost/UUID/dashboard)
	// This ensures canonical URLs and fixes relative path issues.
	// Only do this for GET requests to avoid disrupting form submissions/APIs.
	// EXCLUDE WebSocket upgrades, as browsers don't follow redirects for WS.
	isWS := strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
	if !isPathUUID && cookieUUID != "" && tunnelUUID == cookieUUID && r.Method == http.MethodGet && extraPath == "" && !isWS {
		newPath := "/" + tunnelUUID + r.URL.Path
		if r.URL.RawQuery != "" {
			newPath += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, newPath, http.StatusFound)
		return
	}

	if extraPath != "" {
		// If Browser (HTML), redirect to deep link to fix URL bar
		// e.g. /UUID?token=.../pricing -> /UUID/pricing
		if strings.Contains(r.Header.Get("Accept"), "text/html") {
			// Keep the token in the query if simple redirect loses auth?
			// No, we set a Cookie earlier! So redirect is safe.
			http.Redirect(w, r, "/"+tunnelUUID+extraPath, http.StatusFound)
			return
		}

		// Append the extra path extracted from the token
		if targetPath == "/" {
			targetPath = extraPath
		} else {
			targetPath = strings.TrimRight(targetPath, "/") + extraPath
		}
	}

	proxyRequest(t, w, r, targetPath)
}

func proxyRequest(t *tunnel.Tunnel, w http.ResponseWriter, r *http.Request, path string) {
	log.Printf("👤 User connected: %s -> %s %s", security.GetClientIP(r), r.Method, path)

	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, constants.MaxBodySize)
	}

	stream, err := t.OpenProxyStream()
	if err != nil {
		log.Printf("Proxy: failed to open stream: %v", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		renderTemplate(w, "error.html", map[string]interface{}{
			"Title":   "Tunnel Connection Failed",
			"Message": "Failed to open a stream to the client tunnel. The client may have disconnected.",
		})
		return
	}
	defer stream.Close()

	// Prepare request for forwarding via r.Write
	// strip hop-by-hop headers
	for _, h := range hopByHopHeadersNames {
		r.Header.Del(h)
	}

	// Update URL and Host for the target
	r.URL.Scheme = "http"
	r.URL.Host = fmt.Sprintf("localhost:%d", t.LocalPort)
	// The argument 'path' passed to proxyRequest is the target PATH (without query).
	// e.g. /api/test

	r.URL.Path = path
	// r.URL.RawQuery is already set from the original request.

	r.Host = r.URL.Host
	r.RequestURI = "" // Required by r.Write

	// Write the request to the stream (headers + body)
	if err := r.Write(stream); err != nil {
		log.Printf("Proxy: failed to write request: %v", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		renderTemplate(w, "error.html", map[string]interface{}{
			"Title":   "Request Failed",
			"Message": "Failed to forward request to the local server.",
		})
		return
	}

	br := tunnel.GetBufioReader(stream)
	resp, err := http.ReadResponse(br, r)
	if err != nil {
		tunnel.PutBufioReader(br)
		log.Printf("Proxy: Failed to read response from tunnel: %v", err)
		w.WriteHeader(http.StatusBadGateway)
		renderTemplate(w, "error.html", map[string]interface{}{
			"Title":   "Bad Gateway",
			"Message": "Failed to read response from the local server. The application may have crashed or closed the connection unexpectedly.",
		})
		return
	}

	// Handle WebSocket/Upgrade (101 Switching Protocols)
	if resp.StatusCode == http.StatusSwitchingProtocols {
		// Copy response headers
		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(http.StatusSwitchingProtocols)

		// Hijack the connection to allow raw TCP bidirectional stream
		hj, ok := w.(http.Hijacker)
		if !ok {
			log.Printf("Proxy: server doesn't support hijacking")
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			log.Printf("Proxy: hijack error: %v", err)
			return
		}
		defer conn.Close() // Close the hijacked client connection

		br := tunnel.GetBufioReader(stream)
		defer tunnel.PutBufioReader(br) // recycled when function returns

		resp, err := http.ReadResponse(br, r)
		if err != nil {
			log.Printf("Proxy: Failed to read response from tunnel: %v", err)
			w.WriteHeader(http.StatusBadGateway)
			renderTemplate(w, "error.html", map[string]interface{}{
				"Title":   "Bad Gateway",
				"Message": "Failed to read response from the local server. The application may have crashed or closed the connection unexpectedly.",
			})
			return
		}

		// Defer closing resp.Body (LIFO: runs before PutBufioReader)
		defer func() {
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
		}()

		// Handle WebSocket/Upgrade (101 Switching Protocols)
		if resp.StatusCode == http.StatusSwitchingProtocols {
			// Copy response headers
			for key, values := range resp.Header {
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}
			w.WriteHeader(http.StatusSwitchingProtocols)

			// Hijack the connection to allow raw TCP bidirectional stream
			hj, ok := w.(http.Hijacker)
			if !ok {
				log.Printf("Proxy: server doesn't support hijacking")
				return
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				log.Printf("Proxy: hijack error: %v", err)
				return
			}
			defer conn.Close() // Close the hijacked client connection

			// Prevent deferred resp.Body.Close() from closing the underlying stream (we handle it)
			resp.Body = nil

			// Stream from Client -> Tunnel (stream)
			go func() {
				// We can copy from conn directly to stream
				io.Copy(stream, conn)
			}()

			// Stream from Tunnel (br) -> Client (conn)
			// Use br to capture any bytes extracted from stream but buffered
			io.Copy(conn, br)
			return
		}
	}

	if resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusServiceUnavailable {
		w.WriteHeader(resp.StatusCode)
		renderTemplate(w, "error.html", map[string]interface{}{
			"Title":   "Local Server Unreachable",
			"Message": "The tunnel client could not connect to the local server. Please check if your local application is running and the port is correct.",
		})
		return
	}

	// Rewrite Location header for redirects to include tunnel UUID prefix
	// This ensures users stay within the /{UUID}/ path namespace instead of escaping to root
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := resp.Header.Get("Location")
		if loc != "" && strings.HasPrefix(loc, "/") && !strings.HasPrefix(loc, "/"+t.UUID) {
			// Handle query params if present, don't break them
			resp.Header.Set("Location", "/"+t.UUID+loc)
		}
	}

	for key, values := range resp.Header {
		if !hopByHopHeaders[key] && !dangerousResponseHeaders[key] && key != "Content-Length" {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
	}
	// Explicitly remove Content-Length to avoid mismatches.
	w.Header().Del("Content-Length")

	isHTML := strings.Contains(resp.Header.Get("Content-Type"), "text/html")

	w.WriteHeader(resp.StatusCode)

	// Script to enforce /UUID prefix in History API (fixes Next.js and other SPAs)
	// And Base Tag for relative links.
	injection := fmt.Sprintf(`<head><base href="/%s/"><script>(function(){var p="/%s";var fp=function(u){if(u&&u.startsWith("/")&&!u.startsWith(p)){return u==="/"?p:p+u;}return u;};var op=history.pushState;history.pushState=function(d,t,u){return op.call(this,d,t,fp(u));};var or=history.replaceState;history.replaceState=function(d,t,u){return or.call(this,d,t,fp(u));};})();</script>`, t.UUID, t.UUID)

	if isHTML {
		// Full buffering for HTML to ensure robust replacement (avoid chunk boundary issues)
		bodyBytes, err := io.ReadAll(resp.Body)
		if err == nil {
			// Double quotes replacements
			bodyBytes = bytes.ReplaceAll(bodyBytes, []byte(`src="/`), []byte(fmt.Sprintf(`src="/%s/`, t.UUID)))
			bodyBytes = bytes.ReplaceAll(bodyBytes, []byte(`href="/`), []byte(fmt.Sprintf(`href="/%s/`, t.UUID)))
			bodyBytes = bytes.ReplaceAll(bodyBytes, []byte(`action="/`), []byte(fmt.Sprintf(`action="/%s/`, t.UUID)))
			bodyBytes = bytes.ReplaceAll(bodyBytes, []byte(`"/_next/`), []byte(fmt.Sprintf(`"/%s/_next/`, t.UUID)))

			// Single quotes replacements
			bodyBytes = bytes.ReplaceAll(bodyBytes, []byte(`src='/`), []byte(fmt.Sprintf(`src='/%s/`, t.UUID)))
			bodyBytes = bytes.ReplaceAll(bodyBytes, []byte(`href='/`), []byte(fmt.Sprintf(`href='/%s/`, t.UUID)))
			bodyBytes = bytes.ReplaceAll(bodyBytes, []byte(`action='/`), []byte(fmt.Sprintf(`action='/%s/`, t.UUID)))
			bodyBytes = bytes.ReplaceAll(bodyBytes, []byte(`'/_next/`), []byte(fmt.Sprintf(`'/%s/_next/`, t.UUID)))

			// Inject Head/Script
			if split := bytes.SplitN(bodyBytes, []byte("<head>"), 2); len(split) == 2 {
				bodyBytes = append(split[0], append([]byte(injection), split[1]...)...)
			} else if split := bytes.SplitN(bodyBytes, []byte("<HEAD>"), 2); len(split) == 2 {
				bodyBytes = append(split[0], append([]byte(injection), split[1]...)...)
			}

			w.Write(bodyBytes)
			return
		}
		// If read error, fall through to streaming (unlikely)
	}

	copyBuf := tunnel.GetBuffer()
	if flusher, ok := w.(http.Flusher); ok {
		for {
			n, readErr := resp.Body.Read(copyBuf)
			if n > 0 {
				if _, writeErr := w.Write(copyBuf[:n]); writeErr != nil {
					break
				}
				flusher.Flush()
			}
			if readErr != nil {
				break
			}
		}
	} else {
		io.CopyBuffer(w, resp.Body, copyBuf)
	}
	tunnel.PutBuffer(copyBuf)
}

func cleanup() {
	tunnelMu.Lock()
	defer tunnelMu.Unlock()

	for uuid, t := range tunnels {
		log.Printf("Closing tunnel: %s", uuid)
		t.Close()
	}
}

func isStandardPort(scheme, port string) bool {
	if scheme == "http" && port == "80" {
		return true
	}
	if scheme == "https" && port == "443" {
		return true
	}
	return false
}
