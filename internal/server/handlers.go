package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"ssrok/internal/constants"
	"ssrok/internal/security"
	"ssrok/internal/session"
	"ssrok/internal/tunnel"
	"ssrok/internal/types"
	"ssrok/internal/utils"
)

func (s *Server) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, constants.MsgMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, constants.MaxConfigBodySize)

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
		E2EE:         req.E2EE,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(sessionDuration),
		RequestCount: make(map[string]int),
		LastRequest:  make(map[string]time.Time),
	}

	log.Printf("🔔 Register: New tunnel created: %s", tunnelUUID)
	s.Store.Save(sess)

	scheme := utils.GetScheme(r)
	log.Printf("🌐 Detected scheme: %s (TLS: %v, X-Forwarded-Proto: %s)", scheme, r.TLS != nil, r.Header.Get("X-Forwarded-Proto"))

	// Build host with port for URL
	urlHost := s.Host
	serverPort := s.Port
	if !utils.IsStandardPort(scheme, serverPort) {
		urlHost = s.Host + ":" + serverPort
	}

	var tunnelURL string
	tunnelURL = utils.ConstructURL(scheme, urlHost, tunnelUUID)

	resp := types.ConfigResponse{
		UUID:      tunnelUUID,
		URL:       tunnelURL,
		Token:     token,
		E2EE:      req.E2EE,
		ExpiresIn: sessionDuration,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)

	log.Printf("✅ New tunnel registered: %s (expires in %s)", tunnelUUID, sessionDuration)
}

func (s *Server) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	clientIP := security.GetClientIP(r)

	log.Printf("🔌 WebSocket request received: %s from %s", r.URL.Path, r.Header.Get("Upgrade"))

	if !s.ConnLimiter.TryConnect(clientIP) {
		if s.AuditLogger != nil {
			s.AuditLogger.LogConnectionLimit(clientIP)
		}
		http.Error(w, "Connection limit exceeded", http.StatusTooManyRequests)
		return
	}
	defer s.ConnLimiter.Disconnect(clientIP)

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

	sess, ok := s.Store.Get(tunnelUUID)
	if !ok {
		http.Error(w, constants.MsgTunnelNotFound, http.StatusNotFound)
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" || !sess.VerifyToken(token) {
		if s.AuditLogger != nil {
			s.AuditLogger.LogAuthFailure(clientIP, tunnelUUID, "Invalid or missing token")
		}
		http.Error(w, "Unauthorized: invalid or missing token", http.StatusUnauthorized)
		return
	}

	log.Printf("🔌 WebSocket: Upgrading connection for tunnel: %s", tunnelUUID)
	upgrader := websocket.Upgrader{
		ReadBufferSize:  constants.WSBufferSize,
		WriteBufferSize: constants.WSBufferSize,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("❌ WebSocket upgrade error: %v", err)
		return
	}
	conn.SetReadLimit(int64(constants.MaxWSMessageSize))

	sess.Conn = conn
	sess.TunnelActive = true

	log.Printf("🔔 WebSocket: Client connected, saving session: %s", tunnelUUID)
	s.Store.Save(sess)

	t := tunnel.NewTunnel(tunnelUUID, conn, sess.Port, sess.UseTLS, sess.E2EE)

	s.TunnelMu.Lock()
	s.Tunnels[tunnelUUID] = t
	s.TunnelMu.Unlock()

	log.Printf("🔌 Tunnel connected: %s -> localhost:%d", tunnelUUID, sess.Port)

	if err := t.HandleWebSocket(); err != nil {
		log.Printf("Tunnel error: %v", err)
	}

	t.Close()
	s.TunnelMu.Lock()
	delete(s.Tunnels, tunnelUUID)
	s.TunnelMu.Unlock()

	s.Store.Delete(tunnelUUID)

	log.Printf("🔌 Tunnel disconnected: %s", tunnelUUID)
}

func (s *Server) HandleTunnel(w http.ResponseWriter, r *http.Request) {
	clientIP := security.GetClientIP(r)

	if !s.BruteProtector.Check(clientIP) {
		if s.AuditLogger != nil {
			s.AuditLogger.LogBruteForce(clientIP, "", constants.MaxAuthAttempts)
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
		s.Templates.Render(w, "home.html", map[string]interface{}{
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
		sess, ok = s.Store.Get(tunnelUUID)
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			s.Templates.Render(w, "notfound.html", map[string]interface{}{
				"Title": "Tunnel Not Found",
			})
			return
		}
	} else if cookieUUID != "" {
		sess, ok = s.Store.Get(cookieUUID)
		if ok {
			tunnelUUID = cookieUUID
		}
	}

	if sess == nil {
		if !isPathUUID {
			w.WriteHeader(http.StatusNotFound)
			s.Templates.Render(w, "notfound.html", map[string]interface{}{
				"Title": "Not Found",
			})
			return
		}
	}

	if !sess.CheckRateLimit(clientIP) {
		s.Store.Save(sess)

		if s.AuditLogger != nil {
			s.AuditLogger.LogRateLimit(clientIP, tunnelUUID)
		}

		s.TunnelMu.RLock()
		tLog, okLog := s.Tunnels[tunnelUUID]
		s.TunnelMu.RUnlock()
		if okLog {
			tLog.SendLog(utils.FormatLog("⛔", "RATE", 429, clientIP))
		}

		log.Printf("⛔ Rate limit exceeded: %s", clientIP)
		w.WriteHeader(http.StatusTooManyRequests)
		s.Templates.Render(w, "ratelimit.html", map[string]interface{}{
			"Title": constants.MsgRateLimitExceeded,
		})
		return
	}
	// Save the session with the updated request count/timestamp
	s.Store.Save(sess)

	var authenticated bool
	var extraPath string

	// Check for token in URL (Magic URL / API Key support)
	token := r.URL.Query().Get("token")
	originalToken := token

	if token != "" && !sess.VerifyToken(token) {
		if idx := strings.IndexByte(token, '/'); idx >= 0 {
			attemptToken := token[:idx]
			if sess.VerifyToken(attemptToken) {
				token = attemptToken
				extraPath = originalToken[idx:] // Use originalToken to get the path
				log.Printf("🔹 Parsed malformed token. Token: %s, Path: %s", token, extraPath)
			}
		}
	}

	if token != "" && sess.VerifyToken(token) {
		log.Printf("✅ User logged in (Token): %s", clientIP)

		// Fetch tunnel for logging (if active)
		s.TunnelMu.RLock()
		tLog, okLog := s.Tunnels[tunnelUUID]
		s.TunnelMu.RUnlock()

		if okLog {
			tLog.SendLog(utils.FormatLog("✨", "AUTH", 200, clientIP))
		}

		s.BruteProtector.RecordSuccess(clientIP)
		http.SetCookie(w, &http.Cookie{
			Name:     constants.SessionCookieName,
			Value:    session.SignCookieValue(tunnelUUID),
			Path:     "/",
			MaxAge:   constants.SessionCookieMaxAge,
			HttpOnly: true,
			Secure:   true,
			SameSite: constants.SessionCookieSameSite,
		})

		authenticated = true
	}

	if !authenticated && cookieUUID == tunnelUUID && cookieUUID != "" {
		sessFromCookie, ok := s.Store.Get(cookieUUID)
		if ok && sessFromCookie != nil {
			authenticated = true
			sess = sessFromCookie
		}
	}

	if !authenticated {
		s.TunnelMu.RLock()
		tLog, okLog := s.Tunnels[tunnelUUID]
		s.TunnelMu.RUnlock()

		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, constants.MaxAuthBodySize)

			csrfToken := r.FormValue("csrf_token")
			if !session.VerifyCSRFToken(csrfToken) {
				if s.AuditLogger != nil {
					s.AuditLogger.LogAuthFailure(clientIP, tunnelUUID, "Invalid CSRF token")
				}
				http.Error(w, "Invalid request", http.StatusForbidden)
				return
			}

			password := r.FormValue("password")
			if sess.VerifyPassword(password) {
				log.Printf("✅ User logged in (Password): %s", clientIP)
				if okLog {
					tLog.SendLog(utils.FormatLog("✅", "AUTH", 200, clientIP))
				}

				s.BruteProtector.RecordSuccess(clientIP)
				if s.AuditLogger != nil {
					s.AuditLogger.LogAuthSuccess(clientIP, tunnelUUID)
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
				tLog.SendLog(utils.FormatLog("❌", "AUTH", 401, clientIP))
			}
			s.BruteProtector.RecordFailure(clientIP)
			if s.AuditLogger != nil {
				s.AuditLogger.LogAuthFailure(clientIP, tunnelUUID, "Invalid password")
			}
			csrf := session.SignCSRFToken(session.GenerateCSRFToken())
			w.WriteHeader(http.StatusUnauthorized)
			s.Templates.Render(w, "login.html", map[string]interface{}{
				"Title":     "Login",
				"Error":     "Invalid password",
				"CSRFToken": csrf,
			})
			return
		}

		if okLog {
			tLog.SendLog(utils.FormatLog("🔐", "VIEW", 200, "/login"))
		}
		csrf := session.SignCSRFToken(session.GenerateCSRFToken())
		s.Templates.Render(w, "login.html", map[string]interface{}{
			"Title":     "Login",
			"CSRFToken": csrf,
		})
		return
	}

	s.TunnelMu.RLock()
	t, tunnelExists := s.Tunnels[tunnelUUID]
	s.TunnelMu.RUnlock()

	if !sess.TunnelActive || !tunnelExists {
		w.WriteHeader(http.StatusServiceUnavailable)
		s.Templates.Render(w, "disconnected.html", map[string]interface{}{
			"Title":     "Tunnel Disconnected",
			"Port":      sess.Port,
			"ExpiresIn": time.Until(sess.ExpiresAt).Round(time.Minute).String(),
		})
		return
	}

	var targetPath string
	if isPathUUID {
		targetPath = strings.TrimPrefix(r.URL.Path, "/"+tunnelUUID)
		if targetPath == "" {
			targetPath = "/"
		}
	} else {
		targetPath = r.URL.Path
	}

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
		if strings.Contains(r.Header.Get("Accept"), "text/html") {
			http.Redirect(w, r, "/"+tunnelUUID+extraPath, http.StatusFound)
			return
		}

		if targetPath == "/" {
			targetPath = extraPath
		} else {
			targetPath = strings.TrimRight(targetPath, "/") + extraPath
		}
	}

	s.ProxyRequest(t, w, r, targetPath)
}

func (s *Server) ProxyRequest(t *tunnel.Tunnel, w http.ResponseWriter, r *http.Request, path string) {
	shouldLog := true
	for _, prefix := range constants.IgnoredLogPrefixes {
		if strings.HasPrefix(path, prefix) {
			shouldLog = false
			break
		}
	}

	if shouldLog {
		log.Printf("👤 User connected: %s -> %s %s", security.GetClientIP(r), r.Method, path)
	}

	var bodyBytes []byte
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, constants.MaxBodySize)
		bodyBytes, _ = io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	}

	stream, err := t.OpenProxyStream()
	if err != nil {
		log.Printf("Proxy: failed to open stream: %v", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		s.Templates.Render(w, "error.html", map[string]interface{}{
			"Title":   "Tunnel Connection Failed",
			"Message": "Failed to open a stream to the client tunnel. The client may have disconnected.",
		})
		return
	}
	defer stream.Close()

	for _, h := range utils.HopByHopHeadersNames {
		r.Header.Del(h)
	}

	r.URL.Scheme = "http"
	r.URL.Host = fmt.Sprintf("localhost:%d", t.LocalPort)
	r.URL.Path = path
	r.Host = r.URL.Host
	r.RequestURI = ""

	if err := r.Write(stream); err != nil {
		log.Printf("Proxy: failed to write request: %v", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		s.Templates.Render(w, "error.html", map[string]interface{}{
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
		s.Templates.Render(w, "error.html", map[string]interface{}{
			"Title":   "Bad Gateway",
			"Message": "Failed to read response from the local server. The application may have crashed or closed the connection unexpectedly.",
		})
		return
	}

	defer func() {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		tunnel.PutBufioReader(br)
	}()

	if resp.StatusCode == http.StatusSwitchingProtocols {
		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(http.StatusSwitchingProtocols)

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
		defer conn.Close()

		resp.Body = nil

		go func() {
			io.Copy(stream, conn)
		}()

		io.Copy(conn, br)
		return
	}

	if resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusServiceUnavailable {
		w.WriteHeader(resp.StatusCode)
		s.Templates.Render(w, "error.html", map[string]interface{}{
			"Title":   "Local Server Unreachable",
			"Message": "The tunnel client could not connect to the local server. Please check if your local application is running and the port is correct.",
		})
		return
	}

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := resp.Header.Get("Location")
		if loc != "" && strings.HasPrefix(loc, "/") && !strings.HasPrefix(loc, "/"+t.UUID) {
			resp.Header.Set("Location", "/"+t.UUID+loc)
		}
	}

	for key, values := range resp.Header {
		if !utils.HopByHopHeaders[key] && !utils.DangerousResponseHeaders[key] && key != "Content-Length" {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
	}
	w.Header().Del("Content-Length")

	isHTML := strings.Contains(resp.Header.Get("Content-Type"), "text/html")
	w.WriteHeader(resp.StatusCode)

	injection := fmt.Sprintf(`<head><base href="/%s/"><script>(function(){var p="/%s";var fp=function(u){if(u&&u.startsWith("/")&&!u.startsWith(p)){return u==="/"?p:p+u;}return u;};var op=history.pushState;history.pushState=function(d,t,u){return op.call(this,d,t,fp(u));};var or=history.replaceState;history.replaceState=function(d,t,u){return or.call(this,d,t,fp(u));};})();</script>`, t.UUID, t.UUID)

	if isHTML {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err == nil {
			bodyBytes = bytes.ReplaceAll(bodyBytes, []byte(`src="/`), []byte(fmt.Sprintf(`src="/%s/`, t.UUID)))
			bodyBytes = bytes.ReplaceAll(bodyBytes, []byte(`href="/`), []byte(fmt.Sprintf(`href="/%s/`, t.UUID)))
			bodyBytes = bytes.ReplaceAll(bodyBytes, []byte(`action="/`), []byte(fmt.Sprintf(`action="/%s/`, t.UUID)))
			bodyBytes = bytes.ReplaceAll(bodyBytes, []byte(`"/_next/`), []byte(fmt.Sprintf(`"/%s/_next/`, t.UUID)))

			bodyBytes = bytes.ReplaceAll(bodyBytes, []byte(`src='/`), []byte(fmt.Sprintf(`src='/%s/`, t.UUID)))
			bodyBytes = bytes.ReplaceAll(bodyBytes, []byte(`href='/`), []byte(fmt.Sprintf(`href='/%s/`, t.UUID)))
			bodyBytes = bytes.ReplaceAll(bodyBytes, []byte(`action='/`), []byte(fmt.Sprintf(`action='/%s/`, t.UUID)))
			bodyBytes = bytes.ReplaceAll(bodyBytes, []byte(`'/_next/`), []byte(fmt.Sprintf(`'/%s/_next/`, t.UUID)))

			if split := bytes.SplitN(bodyBytes, []byte("<head>"), 2); len(split) == 2 {
				bodyBytes = append(split[0], append([]byte(injection), split[1]...)...)
			} else if split := bytes.SplitN(bodyBytes, []byte("<HEAD>"), 2); len(split) == 2 {
				bodyBytes = append(split[0], append([]byte(injection), split[1]...)...)
			}

			w.Write(bodyBytes)
			return
		}
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
