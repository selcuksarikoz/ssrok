package tunnel

import (
	"net/http"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"

	"ssrok/internal/constants"
)

var upgrader = websocket.Upgrader{
	CheckOrigin:       func(r *http.Request) bool { return true },
	ReadBufferSize:    constants.WSBufferSize,
	WriteBufferSize:   constants.WSBufferSize,
	EnableCompression: constants.WSCompression,
}

func yamuxConfig() *yamux.Config {
	config := yamux.DefaultConfig()
	config.MaxStreamWindowSize = constants.YamuxMaxStreamWindowSize
	config.AcceptBacklog = constants.YamuxAcceptBacklog
	config.EnableKeepAlive = constants.YamuxEnableKeepAlive
	config.KeepAliveInterval = constants.YamuxKeepAliveInterval
	return config
}
