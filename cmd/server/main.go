package main

import (
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
	"strconv"
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

	baseTmpl, err := template.New("layout").Parse(string(layoutContent))
	if err != nil {
		return nil, err
	}

	pages := []string{"login.html", "ratelimit.html", "notfound.html", "home.html"}

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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	templates[name].Execute(w, data)
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

func gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") ||
			r.Header.Get("Upgrade") == "websocket" {
			next.ServeHTTP(w, r)
			return
		}

		gz := tunnel.GetGzipWriter(w)

		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Del("Content-Length")
		next.ServeHTTP(&gzipResponseWriter{ResponseWriter: w, Writer: gz}, r)

		tunnel.PutGzipWriter(gz)
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

	var handler http.Handler = mux
	handler = security.SecurityHeaders(handler)
	handler = gzipMiddleware(handler)

	port := utils.GetEnv("PORT", constants.DefaultPort)
	certFile := utils.GetEnv("SSROK_CERT_FILE", "certs/server.crt")
	keyFile := utils.GetEnv("SSROK_KEY_FILE", "certs/server.key")

	log.Printf("🚀 ssrok server starting on :%s", port)

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
		Addr:              ":" + port,
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

	scheme := "http"
	if serverUseTLS {
		scheme = "https"
	}

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

	conn, err := websocket.Upgrade(w, r, nil, constants.WSBufferSize, constants.WSBufferSize)
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
		if auditLogger != nil {
			auditLogger.LogRateLimit(clientIP, tunnelUUID)
		}
		log.Printf("⛔ Rate limit exceeded: %s", clientIP)
		w.WriteHeader(http.StatusTooManyRequests)
		renderTemplate(w, "ratelimit.html", map[string]interface{}{
			"Title": constants.MsgRateLimitExceeded,
		})
		return
	}

	token := r.URL.Query().Get("token")

	if token != "" && sess.VerifyToken(token) {
		log.Printf("✅ User logged in (Token): %s", clientIP)
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

		cleanURL := "/" + tunnelUUID
		if len(parts) > 1 {
			cleanURL += "/" + strings.Join(parts[1:], "/")
		}

		http.Redirect(w, r, cleanURL, http.StatusFound)
		return
	}

	var authenticated bool

	if cookieUUID == tunnelUUID && cookieUUID != "" {
		authenticated = true
	}

	if sess.HasPassword() && !authenticated {
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

		csrf := session.SignCSRFToken(session.GenerateCSRFToken())
		renderTemplate(w, "login.html", map[string]interface{}{
			"Title":     "Login",
			"CSRFToken": csrf,
		})
		return
	} else if !authenticated {
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

	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, constants.MaxBodySize)
	}

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

	buf := tunnel.GetBytesBuffer()

	buf.WriteString(r.Method)
	buf.WriteByte(' ')
	buf.WriteString(path)
	buf.WriteString(" HTTP/1.1\r\n")

	for key, values := range r.Header {
		if !hopByHopHeaders[key] && !sensitiveRequestHeaders[key] {
			for _, value := range values {
				buf.WriteString(key)
				buf.WriteString(": ")
				buf.WriteString(value)
				buf.WriteString("\r\n")
			}
		}
	}

	buf.WriteString("Host: localhost:")
	buf.WriteString(strconv.Itoa(t.LocalPort))
	buf.WriteString("\r\n")

	clientIP := security.GetClientIP(r)
	buf.WriteString("X-Forwarded-For: ")
	buf.WriteString(clientIP)
	buf.WriteString("\r\n")

	buf.WriteString("X-Forwarded-Host: ")
	buf.WriteString(r.Host)
	buf.WriteString("\r\n")

	buf.WriteString("X-Forwarded-Proto: ")
	buf.WriteString(getScheme(r))
	buf.WriteString("\r\n")

	if r.ContentLength > 0 {
		buf.WriteString("Content-Length: ")
		buf.WriteString(strconv.FormatInt(r.ContentLength, 10))
		buf.WriteString("\r\n")
	}

	buf.WriteString("\r\n")

	if _, err := stream.Write(buf.Bytes()); err != nil {
		tunnel.PutBytesBuffer(buf)
		http.Error(w, "Failed to write request", http.StatusServiceUnavailable)
		return
	}
	tunnel.PutBytesBuffer(buf)

	if r.Body != nil {
		reqBuf := tunnel.GetBuffer()
		io.CopyBuffer(stream, r.Body, reqBuf)
		tunnel.PutBuffer(reqBuf)
		r.Body.Close()
	}

	br := tunnel.GetBufioReader(stream)
	resp, err := http.ReadResponse(br, r)
	if err != nil {
		tunnel.PutBufioReader(br)
		log.Printf("Proxy: Failed to read response from tunnel: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		if !hopByHopHeaders[key] && !dangerousResponseHeaders[key] {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
	}
	w.WriteHeader(resp.StatusCode)

	copyBuf := tunnel.GetBuffer()
	if flusher, ok := w.(http.Flusher); ok {
		for {
			n, readErr := br.Read(copyBuf)
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
		io.CopyBuffer(w, br, copyBuf)
	}
	tunnel.PutBuffer(copyBuf)
	tunnel.PutBufioReader(br)
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
