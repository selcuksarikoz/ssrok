package tunnel

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/yamux"

	"ssrok/internal/constants"
	"ssrok/internal/crypto"
	"ssrok/internal/types"
	"ssrok/internal/utils"
)

func (t *Tunnel) handleStream(stream net.Conn) {
	defer stream.Close()

	typeBuf := make([]byte, 1)
	if _, err := io.ReadFull(stream, typeBuf); err != nil {
		return
	}

	if typeBuf[0] == constants.StreamTypeLog {
		msg, err := io.ReadAll(stream)
		if err == nil && len(msg) > 0 {
			msgStr := string(msg)
			if t.SecurityCallback != nil && (strings.HasPrefix(msgStr, "🔒") || strings.HasPrefix(msgStr, "⛔")) {
				t.SecurityCallback(msgStr)
			} else if t.LogCallback != nil {
				t.LogCallback(msgStr)
			}
		}
		return
	}

	if typeBuf[0] == constants.StreamTypeStats {
		msg, _ := io.ReadAll(stream)
		if len(msg) > 0 {
			var stats map[string]int64
			if json.Unmarshal(msg, &stats) == nil {
				if v, ok := stats["blocked"]; ok {
					atomic.StoreInt64(&t.Blocked, v)
				}
				if v, ok := stats["rate_limited"]; ok {
					atomic.StoreInt64(&t.RateLimited, v)
				}
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
	requestLogger := &utils.LimitedBuffer{Buf: &requestLogBuf, Limit: constants.MaxLogBufferSize}
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
	responseLogger := &utils.LimitedBuffer{Buf: &responseLogBuf, Limit: constants.MaxLogBufferSize}
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

		if t.LogCallback != nil {
			t.LogCallback(logLine)
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

	// Flush pending logs
	go func() {
		for msg := range t.pendingLogs {
			t.sendLogMessage(msg)
		}
	}()

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
			errStr := err.Error()
			if strings.Contains(errStr, "websocket: close") || strings.Contains(errStr, "abnormal closure") {
				return fmt.Errorf("server closed the connection")
			}
			return fmt.Errorf("failed to accept stream: %w", err)
		}

		go t.handleStream(stream)
	}
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

// SendLog sends a log message to the client
func (t *Tunnel) SendLog(message string) error {
	if t.Session == nil {
		select {
		case t.pendingLogs <- message:
			return nil
		default:
			return fmt.Errorf("pending logs channel full")
		}
	}
	return t.sendLogMessage(message)
}

func (t *Tunnel) sendLogMessage(message string) error {
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

func (t *Tunnel) IncBlocked() {
	atomic.AddInt64(&t.Blocked, 1)
	t.SendStats()
}

func (t *Tunnel) IncRateLimited() {
	atomic.AddInt64(&t.RateLimited, 1)
	t.SendStats()
}

func (t *Tunnel) SendStats() {
	stats := map[string]int64{
		"blocked":      atomic.LoadInt64(&t.Blocked),
		"rate_limited": atomic.LoadInt64(&t.RateLimited),
	}
	data, _ := json.Marshal(stats)
	if t.Session == nil {
		return
	}
	stream, err := t.Session.OpenStream()
	if err != nil {
		return
	}
	defer stream.Close()
	stream.Write([]byte{constants.StreamTypeStats})
	stream.Write(data)
}
