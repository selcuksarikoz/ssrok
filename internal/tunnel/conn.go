package tunnel

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"ssrok/internal/logger"
)

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
