package tunnel

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
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
}

func NewTunnel(uuid string, wsConn *websocket.Conn, localPort int, useTLS bool) *Tunnel {
	return &Tunnel{
		UUID:      uuid,
		WSConn:    wsConn,
		LocalPort: localPort,
		UseTLS:    useTLS,
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
	wsWrapper := &wsConnWrapper{conn: t.WSConn}

	session, err := yamux.Server(wsWrapper, yamuxConfig())
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

func (t *Tunnel) handleStream(stream net.Conn) {
	defer stream.Close()

	// Read stream type
	typeBuf := make([]byte, 1)
	if _, err := io.ReadFull(stream, typeBuf); err != nil {
		return
	}

	if typeBuf[0] == constants.StreamTypeLog {
		// Log message stream
		msg, err := io.ReadAll(stream)
		if err == nil && len(msg) > 0 {
			if t.LogCallback != nil {
				t.LogCallback(string(msg))
			} else {
				// Default fallback
				fmt.Printf("Remote: %s\n", string(msg))
			}
		}
		return
	}

	// Constants.StreamTypeProxy or unknown (treat as proxy for robustness if feasible, but better strict)
	// If it's not proxy, we could error, but let's assume it is normal traffic if not log.
	if typeBuf[0] != constants.StreamTypeProxy {
		return
	}

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

	errChan := make(chan error, 2)

	go func() {
		_, err := io.CopyBuffer(localConn, stream, buf1)
		if tc, ok := localConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		errChan <- err
	}()

	go func() {
		_, err := io.CopyBuffer(stream, localConn, buf2)
		errChan <- err
	}()

	<-errChan
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
}

func (w *wsConnWrapper) Read(p []byte) (n int, err error) {
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
	if n > 0 && w.log != nil {
		w.log.LogData("server->client", p[:n], w.conn.RemoteAddr().String(), w.localPort)
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
	return len(p), nil
}

func (w *wsConnWrapper) Close() error                       { return w.conn.Close() }
func (w *wsConnWrapper) LocalAddr() net.Addr                { return w.conn.LocalAddr() }
func (w *wsConnWrapper) RemoteAddr() net.Addr               { return w.conn.RemoteAddr() }
func (w *wsConnWrapper) SetDeadline(t time.Time) error      { return nil }
func (w *wsConnWrapper) SetReadDeadline(t time.Time) error  { return w.conn.SetReadDeadline(t) }
func (w *wsConnWrapper) SetWriteDeadline(t time.Time) error { return w.conn.SetWriteDeadline(t) }

func ConnectClient(wsURL string, targetAddr string, sessionID string, skipTLSVerify bool, useTLS bool) (*Tunnel, error) {
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

	session, err := yamux.Client(wsWrapper, yamuxConfig())
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
		UseTLS:    useTLS,
		log:       log,
		localAddr: targetAddr,
		LogCallback: func(msg string) {
			fmt.Printf("  %s%s%s\n", constants.ColorCyan, msg, constants.ColorReset)
		},
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
