package tunnel

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"

	"ssrok/internal/constants"
	"ssrok/internal/crypto"
	"ssrok/internal/logger"
)

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
		errMsg := "failed to connect to server"
		if resp != nil && resp.StatusCode == 404 {
			errMsg = "server not found (is the server running?)"
		} else if resp != nil {
			errMsg = fmt.Sprintf("server returned %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("%s", errMsg)
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
