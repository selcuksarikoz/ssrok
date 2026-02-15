package tunnel

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"

	"ssrok/internal/constants"
	"ssrok/internal/logger"
)

var upgrader = websocket.Upgrader{
	CheckOrigin:       func(r *http.Request) bool { return true },
	ReadBufferSize:    constants.WSBufferSize,
	WriteBufferSize:   constants.WSBufferSize,
	EnableCompression: false, // Disable compression for speed (CPU trade-off)
}

type Tunnel struct {
	UUID      string
	WSConn    *websocket.Conn
	Session   *yamux.Session
	LocalPort int
	UseTLS    bool
	mu        sync.RWMutex
	isClosed  bool
	log       *logger.Logger
}

// NewTunnel creates a new tunnel instance
func NewTunnel(uuid string, wsConn *websocket.Conn, localPort int, useTLS bool) *Tunnel {
	return &Tunnel{
		UUID:      uuid,
		WSConn:    wsConn,
		LocalPort: localPort,
		UseTLS:    useTLS,
	}
}

// HandleWebSocket establishes yamux session over WebSocket
func (t *Tunnel) HandleWebSocket() error {
	wsWrapper := &wsConnWrapper{conn: t.WSConn}

	// Optimized yamux config for high throughput
	config := yamux.DefaultConfig()
	config.MaxStreamWindowSize = 1024 * 1024 // 1MB window for fast transfers
	config.AcceptBacklog = 256               // Higher backlog for concurrent streams
	config.EnableKeepAlive = true
	config.KeepAliveInterval = 30 * time.Second

	session, err := yamux.Server(wsWrapper, config)
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

func (t *Tunnel) handleStream(stream net.Conn) {
	defer stream.Close()

	var localConn net.Conn
	var err error

	if t.UseTLS {
		localConn, err = tls.Dial("tcp", fmt.Sprintf("localhost:%d", t.LocalPort), &tls.Config{InsecureSkipVerify: true})
	} else {
		localConn, err = net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", t.LocalPort), constants.DialTimeout)
	}
	if err != nil {
		stream.Write([]byte(fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\n\r\nFailed to connect to local server: %v", err)))
		return
	}
	defer localConn.Close()

	// Disable Nagle algorithm for low latency
	if tcpConn, ok := localConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	// Use pooled buffers for zero-allocation copy
	buf1 := GetBuffer()
	buf2 := GetBuffer()
	defer PutBuffer(buf1)
	defer PutBuffer(buf2)

	errChan := make(chan error, 2)

	go func() {
		_, err := io.CopyBuffer(localConn, stream, buf1)
		errChan <- err
	}()

	go func() {
		_, err := io.CopyBuffer(stream, localConn, buf2)
		errChan <- err
	}()

	<-errChan
}

// Close closes the tunnel
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

// GetLogPath returns the path to the log file
func (t *Tunnel) GetLogPath() string {
	if t.log != nil {
		return t.log.GetLogPath()
	}
	return ""
}

// wsConnWrapper wraps WebSocket to implement net.Conn
type wsConnWrapper struct {
	conn      *websocket.Conn
	reader    io.Reader
	mu        sync.Mutex
	log       *logger.Logger
	localPort int
	isClient  bool
}

func (w *wsConnWrapper) Read(p []byte) (n int, err error) {
	if w.reader == nil {
		_, w.reader, err = w.conn.NextReader()
		if err != nil {
			if w.log != nil {
				direction := "server->client"
				if w.isClient {
					direction = "server->client"
				}
				w.log.LogError(direction, err, w.conn.RemoteAddr().String(), w.localPort)
			}
			return 0, err
		}
	}

	n, err = w.reader.Read(p)
	if err != nil && err != io.EOF {
		if w.log != nil {
			direction := "server->client"
			w.log.LogError(direction, err, w.conn.RemoteAddr().String(), w.localPort)
		}
	}
	if err == io.EOF {
		w.reader = nil
		err = nil
	}
	if n > 0 && w.log != nil {
		direction := "server->client"
		w.log.LogData(direction, p[:n], w.conn.RemoteAddr().String(), w.localPort)
	}
	return n, err
}

func (w *wsConnWrapper) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	err = w.conn.WriteMessage(websocket.BinaryMessage, p)
	if err != nil {
		if w.log != nil {
			direction := "client->server"
			w.log.LogError(direction, err, w.conn.RemoteAddr().String(), w.localPort)
		}
		return 0, err
	}
	if w.log != nil {
		direction := "client->server"
		w.log.LogData(direction, p, w.conn.RemoteAddr().String(), w.localPort)
	}
	return len(p), nil
}

func (w *wsConnWrapper) Close() error {
	return w.conn.Close()
}

func (w *wsConnWrapper) LocalAddr() net.Addr {
	return w.conn.LocalAddr()
}

func (w *wsConnWrapper) RemoteAddr() net.Addr {
	return w.conn.RemoteAddr()
}

func (w *wsConnWrapper) SetDeadline(t time.Time) error {
	return nil
}

func (w *wsConnWrapper) SetReadDeadline(t time.Time) error {
	return w.conn.SetReadDeadline(t)
}

func (w *wsConnWrapper) SetWriteDeadline(t time.Time) error {
	return w.conn.SetWriteDeadline(t)
}

// ConnectClient establishes client-side tunnel connection
func ConnectClient(wsURL string, localPort int, sessionID string, skipTLSVerify bool) (*Tunnel, error) {
	log, err := logger.NewLogger(sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}

	log.LogEvent(fmt.Sprintf("Connecting to WebSocket: %s", wsURL), localPort)

	// Create dialer with TLS config based on skipTLSVerify
	dialer := &websocket.Dialer{
		ReadBufferSize:    constants.WSBufferSize,
		WriteBufferSize:   constants.WSBufferSize,
		EnableCompression: false,
		HandshakeTimeout:  10 * time.Second,
	}

	if skipTLSVerify {
		dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		log.LogError("client->server", fmt.Errorf("failed to connect to server: %w", err), "", localPort)
		log.Close()
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}

	remoteAddr := conn.RemoteAddr().String()
	log.LogEvent(fmt.Sprintf("WebSocket connected to %s", remoteAddr), localPort)

	wsWrapper := &wsConnWrapper{
		conn:      conn,
		log:       log,
		localPort: localPort,
		isClient:  true,
	}

	// Optimized yamux config for client
	config := yamux.DefaultConfig()
	config.MaxStreamWindowSize = 1024 * 1024 // 1MB window
	config.AcceptBacklog = 256
	config.EnableKeepAlive = true
	config.KeepAliveInterval = 30 * time.Second

	session, err := yamux.Client(wsWrapper, config)
	if err != nil {
		log.LogError("client", fmt.Errorf("failed to create yamux client: %w", err), remoteAddr, localPort)
		conn.Close()
		log.Close()
		return nil, fmt.Errorf("failed to create yamux client: %w", err)
	}

	log.LogEvent("Yamux session established", localPort)

	tunnel := &Tunnel{
		UUID:      sessionID,
		WSConn:    conn,
		Session:   session,
		LocalPort: localPort,
		log:       log,
	}

	return tunnel, nil
}
