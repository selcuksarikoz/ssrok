package tunnel

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"

	"ssrok/internal/constants"
	"ssrok/internal/crypto"
	"ssrok/internal/dashboard"
	"ssrok/internal/logger"
	"ssrok/internal/types"
	"ssrok/internal/utils"
)

var upgrader = websocket.Upgrader{
	CheckOrigin:       func(r *http.Request) bool { return true },
	ReadBufferSize:    constants.WSBufferSize,
	WriteBufferSize:   constants.WSBufferSize,
	EnableCompression: false,
}

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

func (t *Tunnel) Logger() *logger.Logger {
	return t.log
}

func (t *Tunnel) SetDashboard(d *dashboard.Dashboard) {
	t.dashboard = d
}

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

func yamuxConfig() *yamux.Config {
	config := yamux.DefaultConfig()
	config.MaxStreamWindowSize = 4 * 1024 * 1024
	config.AcceptBacklog = 512
	config.EnableKeepAlive = true
	config.KeepAliveInterval = 30 * time.Second
	return config
}

func (t *Tunnel) HandleWebSocket() error {
	wsWrapper := &wsConnWrapper{conn: t.WSConn, tunnel: t}
	var tunnelConn net.Conn = wsWrapper

	if t.E2EE {
		sharedSecret, err := crypto.Handshake(wsWrapper, true)
		if err != nil {
			return fmt.Errorf("E2EE handshake failed: %w", err)
		}

		secureConn, err := crypto.NewSecureConn(wsWrapper, sharedSecret)
		if err != nil {
			return fmt.Errorf("failed to create secure connection: %w", err)
		}
		tunnelConn = secureConn
	}

	session, err := yamux.Server(tunnelConn, yamuxConfig())
	if err != nil {
		return fmt.Errorf("failed to create yamux session: %w", err)
	}

	t.Session = session

	for {
		stream, err := session.AcceptStream()
		if err != nil {
			if t.isClosed {
				return nil
			}
			return fmt.Errorf("failed to accept stream: %w", err)
		}

		go t.handleStream(stream)
	}
}

func (t *Tunnel) Process() error {
	if t.Session == nil {
		return fmt.Errorf("tunnel session not initialized")
	}

	for {
		stream, err := t.Session.AcceptStream()
		if err != nil {
			if t.isClosed {
				return nil
			}
			return fmt.Errorf("failed to accept stream: %w", err)
		}

		go t.handleStream(stream)
	}
}

type limitedBuffer struct {
	buf     *bytes.Buffer
	limit   int
	written int
}

func (l *limitedBuffer) Write(p []byte) (n int, err error) {
	if l.written >= l.limit {
		return len(p), nil
	}
	remaining := l.limit - l.written
	if len(p) > remaining {
		l.buf.Write(p[:remaining])
		l.written += remaining
		return len(p), nil
	}
	n, err = l.buf.Write(p)
	l.written += n
	return n, err
}

func (t *Tunnel) handleStream(stream net.Conn) {
	defer stream.Close()

	typeBuf := make([]byte, 1)
	if _, err := io.ReadFull(stream, typeBuf); err != nil {
		return
	}

	if typeBuf[0] == constants.StreamTypeLog {
		msg, err := io.ReadAll(stream)
		if err == nil && len(msg) > 0 {
			if t.LogCallback != nil {
				t.LogCallback(string(msg))
			} else {
				fmt.Printf("Remote: %s\n", string(msg))
			}
		}
		return
	}

	if typeBuf[0] != constants.StreamTypeProxy {
		return
	}

	// Update stats
	atomic.AddInt64(&t.TotalReqs, 1)
	atomic.AddInt64(&t.ActiveConns, 1)
	if t.dashboard != nil {
		t.dashboard.IncActive()
	}
	defer func() {
		atomic.AddInt64(&t.ActiveConns, -1)
		if t.dashboard != nil {
			t.dashboard.DecActive()
		}
	}()

	startTime := time.Now()
	logID := uuid.New().String()

	var requestLogBuf bytes.Buffer
	requestLogger := &limitedBuffer{buf: &requestLogBuf, limit: 1024 * 1024}
	loggedStream := io.TeeReader(stream, requestLogger)

	var localConn net.Conn
	var err error

	if t.log != nil {
		t.log.LogEvent("Forwarding request", t.LocalPort)
	}

	if t.UseTLS {
		localConn, err = tls.Dial("tcp", t.localAddr, &tls.Config{InsecureSkipVerify: true})
	} else {
		localConn, err = net.DialTimeout("tcp", t.localAddr, constants.DialTimeout)
	}
	if err != nil {
		if t.log != nil {
			t.log.LogError("local app connection failed", err, t.localAddr, t.LocalPort)
		}
		stream.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\nFailed to connect to local server"))
		return
	}
	defer localConn.Close()

	if tcpConn, ok := localConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	buf1 := GetBuffer()
	buf2 := GetBuffer()
	defer PutBuffer(buf1)
	defer PutBuffer(buf2)

	var responseLogBuf bytes.Buffer
	responseLogger := &limitedBuffer{buf: &responseLogBuf, limit: 1024 * 1024}
	loggedLocalConn := io.TeeReader(localConn, responseLogger)

	errChan := make(chan error, 2)

	go func() {
		reader := bufio.NewReader(loggedStream)
		var headerBuf bytes.Buffer

		// Read request line
		line, err := reader.ReadString('\n')
		headerBuf.WriteString(line)

		if err == nil {
			for {
				line, err = reader.ReadString('\n')
				headerBuf.WriteString(line)
				if err != nil || line == "\r\n" {
					break
				}
			}
		}

		// Write captured headers to local connection
		if headerBuf.Len() > 0 {
			if _, err := localConn.Write(headerBuf.Bytes()); err != nil {
				errChan <- err
				return
			}
		}

		// Copy the rest of the stream using the buffered reader
		_, err = io.CopyBuffer(localConn, reader, buf1)
		if tc, ok := localConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		errChan <- err
	}()

	go func() {
		// Capture response via loggedLocalConn
		_, err := io.CopyBuffer(stream, loggedLocalConn, buf2)
		errChan <- err
	}()

	// Wait for both directions to finish
	<-errChan
	localConn.Close() // Signal other direction to stop if it hasn't
	stream.Close()
	<-errChan

	duration := time.Since(startTime)

	// Parse Logs from captured buffers
	var method, path, userAgent, clientIP string
	var reqHeaders, respHeaders map[string][]string
	var reqBody, respBody string
	var queryParams map[string][]string
	var statusCode int

	// Parse Request
	reqReader := bufio.NewReader(&requestLogBuf)
	req, err := http.ReadRequest(reqReader)
	if err == nil {
		method = req.Method
		path = req.URL.Path
		userAgent = req.UserAgent()
		reqHeaders = req.Header
		queryParams = req.URL.Query()

		if fwd := req.Header.Get("X-Forwarded-For"); fwd != "" {
			parts := strings.Split(fwd, ",")
			if len(parts) > 0 {
				clientIP = strings.TrimSpace(parts[0])
			}
		}

		if b, err := io.ReadAll(req.Body); err == nil && len(b) > 0 {
			reqBody = string(b)
		}
	} else {
		logStr := requestLogBuf.String()
		if idx := strings.Index(logStr, "\n"); idx > 0 {
			line := logStr[:idx]
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				method = parts[0]
				path = parts[1]
			}
		}
	}

	// Parse Response
	respReader := bufio.NewReader(&responseLogBuf)
	if resp, err := http.ReadResponse(respReader, req); err == nil {
		statusCode = resp.StatusCode
		respHeaders = resp.Header
		if b, err := io.ReadAll(resp.Body); err == nil && len(b) > 0 {
			respBody = string(b)
		}
	} else {
		logStr := responseLogBuf.String()
		if idx := strings.Index(logStr, "\n"); idx > 0 {
			line := logStr[:idx]
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				if code, err := strconv.Atoi(parts[1]); err == nil {
					statusCode = code
				}
			}
		}
	}

	// Filter logs from ignored prefixes
	shouldLog := true
	for _, prefix := range constants.IgnoredLogPrefixes {
		if strings.HasPrefix(path, prefix) {
			shouldLog = false
			break
		}
	}

	if shouldLog && method != "" {
		if t.log != nil {
			go t.log.LogHTTP(method, path, statusCode, duration, userAgent, t.LocalPort)
		}

		logLine := utils.FormatLog("", method, statusCode, path)

		// Use callback if available (for TUI), otherwise print to stdout
		if t.LogCallback != nil {
			t.LogCallback(logLine)
		} else {
			fmt.Print(logLine)
		}
	}

	if shouldLog && t.dashboard != nil {
		go t.dashboard.AddLog(types.HTTPLog{
			ID:         logID,
			Method:     method,
			Path:       path,
			StatusCode: statusCode,
			Duration:   duration,
			Timestamp:  startTime,
			UserAgent:  userAgent,
			ClientIP:   clientIP,
			Request: types.RequestDetails{
				Headers:     reqHeaders,
				Body:        reqBody,
				QueryParams: queryParams,
			},
			Response: types.ResponseDetails{
				Headers: respHeaders,
				Body:    respBody,
			},
		})
	}
}

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

func (t *Tunnel) GetLogPath() string {
	if t.log != nil {
		return t.log.GetLogPath()
	}
	return ""
}

type wsConnWrapper struct {
	conn      *websocket.Conn
	reader    io.Reader
	mu        sync.Mutex
	log       *logger.Logger
	localPort int
	isClient  bool
	tunnel    *Tunnel
}

func (w *wsConnWrapper) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if w.reader == nil {
		_, w.reader, err = w.conn.NextReader()
		if err != nil {
			if w.log != nil {
				w.log.LogError("server->client", err, w.conn.RemoteAddr().String(), w.localPort)
			}
			return 0, err
		}
	}

	n, err = w.reader.Read(p)
	if err != nil && err != io.EOF {
		if w.log != nil {
			w.log.LogError("server->client", err, w.conn.RemoteAddr().String(), w.localPort)
		}
	}
	if err == io.EOF {
		w.reader = nil
		err = nil
	}
	if n > 0 {
		if w.log != nil {
			w.log.LogData("server->client", p[:n], w.conn.RemoteAddr().String(), w.localPort)
		}
		if w.tunnel != nil {
			atomic.AddInt64(&w.tunnel.BytesIn, int64(n))
		}
	}
	return n, err
}

func (w *wsConnWrapper) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	err = w.conn.WriteMessage(websocket.BinaryMessage, p)
	if err != nil {
		if w.log != nil {
			w.log.LogError("client->server", err, w.conn.RemoteAddr().String(), w.localPort)
		}
		return 0, err
	}
	if w.log != nil {
		w.log.LogData("client->server", p, w.conn.RemoteAddr().String(), w.localPort)
	}
	if w.tunnel != nil {
		atomic.AddInt64(&w.tunnel.BytesOut, int64(len(p)))
	}
	return len(p), nil
}

func (w *wsConnWrapper) Close() error                       { return w.conn.Close() }
func (w *wsConnWrapper) LocalAddr() net.Addr                { return w.conn.LocalAddr() }
func (w *wsConnWrapper) RemoteAddr() net.Addr               { return w.conn.RemoteAddr() }
func (w *wsConnWrapper) SetDeadline(t time.Time) error      { return nil }
func (w *wsConnWrapper) SetReadDeadline(t time.Time) error  { return w.conn.SetReadDeadline(t) }
func (w *wsConnWrapper) SetWriteDeadline(t time.Time) error { return w.conn.SetWriteDeadline(t) }

func ConnectClient(wsURL string, targetAddr string, sessionID string, skipTLSVerify bool, useTLS bool, e2ee bool) (*Tunnel, error) {
	_, portStr, _ := net.SplitHostPort(targetAddr)
	localPort, _ := strconv.Atoi(portStr)

	log, err := logger.NewLogger(sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}

	log.LogEvent(fmt.Sprintf("Connecting to WebSocket: %s", wsURL), localPort)

	dialer := &websocket.Dialer{
		ReadBufferSize:    constants.WSBufferSize,
		WriteBufferSize:   constants.WSBufferSize,
		EnableCompression: false,
		HandshakeTimeout:  constants.WSHandshakeTimeout,
	}

	if skipTLSVerify {
		log.LogEvent(fmt.Sprintf("TLS verify skip enabled for: %s", wsURL), localPort)
		dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	log.LogEvent("Dialing WebSocket...", localPort)
	conn, resp, err := dialer.Dial(wsURL, nil)
	if err != nil {
		log.LogError("client->server", fmt.Errorf("failed to connect to server: %w", err), "", localPort)
		log.Close()
		return nil, fmt.Errorf("failed to connect to server: %w (resp: %+v)", err, resp)
	}
	conn.SetReadLimit(int64(constants.MaxWSMessageSize))

	remoteAddr := conn.RemoteAddr().String()
	log.LogEvent(fmt.Sprintf("WebSocket connected to %s", remoteAddr), localPort)

	tunnel := &Tunnel{
		UUID:      sessionID,
		WSConn:    conn,
		LocalPort: localPort,
		UseTLS:    useTLS,
		E2EE:      e2ee,
		log:       log,
		localAddr: targetAddr,
	}

	wsWrapper := &wsConnWrapper{
		conn:      conn,
		log:       log,
		localPort: localPort,
		isClient:  true,
		tunnel:    tunnel,
	}

	var tunnelConn net.Conn = wsWrapper

	if e2ee {
		log.LogEvent("E2EE enabled, performing handshake...", localPort)
		sharedSecret, err := crypto.Handshake(wsWrapper, false)
		if err != nil {
			conn.Close()
			log.Close()
			return nil, fmt.Errorf("E2EE handshake failed: %w", err)
		}

		secureConn, err := crypto.NewSecureConn(wsWrapper, sharedSecret)
		if err != nil {
			conn.Close()
			log.Close()
			return nil, fmt.Errorf("failed to create secure connection: %w", err)
		}
		tunnelConn = secureConn
		log.LogEvent("E2EE handshake successful", localPort)
	}

	session, err := yamux.Client(tunnelConn, yamuxConfig())
	if err != nil {
		log.LogError("client", fmt.Errorf("failed to create yamux client: %w", err), remoteAddr, localPort)
		conn.Close()
		log.Close()
		return nil, fmt.Errorf("failed to create yamux client: %w", err)
	}

	tunnel.Session = session

	log.LogEvent("Yamux session established", localPort)

	tunnel.LogCallback = func(msg string) {
		fmt.Printf("  %s%s%s\n", constants.ColorCyan, msg, constants.ColorReset)
	}

	return tunnel, nil
}

// SendLog sends a log message to the client
func (t *Tunnel) SendLog(message string) error {
	if t.Session == nil {
		return fmt.Errorf("session not initialized")
	}
	stream, err := t.Session.OpenStream()
	if err != nil {
		return err
	}
	defer stream.Close()

	// Write type byte
	if _, err := stream.Write([]byte{constants.StreamTypeLog}); err != nil {
		return err
	}
	// Write message
	if _, err := stream.Write([]byte(message)); err != nil {
		return err
	}
	return nil
}

// OpenProxyStream opens a stream for proxying HTTP traffic
func (t *Tunnel) OpenProxyStream() (net.Conn, error) {
	if t.Session == nil {
		return nil, fmt.Errorf("session not initialized")
	}
	stream, err := t.Session.OpenStream()
	if err != nil {
		return nil, err
	}

	// Write type byte
	if _, err := stream.Write([]byte{constants.StreamTypeProxy}); err != nil {
		stream.Close()
		return nil, err
	}
	return stream, nil
}
