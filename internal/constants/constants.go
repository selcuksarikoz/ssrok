package constants

import (
	"net/http"
	"time"
)

const (
	DefaultHost = "localhost"
	DefaultPort = "80"
)

var (
	// DefaultServerURL can be overwritten at build time using -ldflags
	DefaultServerURL = "http://localhost"

	// Version can be overwritten at build time using -ldflags
	Version = "0.1.3"
)

const (
	MinPort         = 1
	MaxPort         = 65535
	BufferSize      = 131072 // 128KB
	WSBufferSize    = 131072 // 128KB
	CopyBufferSize  = 524288 // 512KB
	DialTimeout     = 5 * time.Second
	CleanupInterval = 30 * time.Second
	StreamTypeProxy = 0x00
	StreamTypeLog   = 0x01
)

const (
	SessionDuration       = time.Hour
	MinSessionDuration    = 5 * time.Minute
	MaxSessionDuration    = 24 * time.Hour
	SessionCookieName     = "ssrok_session"
	SessionCookieMaxAge   = 3600
	SessionCookieSameSite = http.SameSiteStrictMode
)

const (
	DefaultRateLimit    = 60
	RateLimitWindow     = time.Minute
	UnlimitedRateLimit  = 0
	MaxConnectionsPerIP = 10
	MaxBodySize         = 100 * 1024 * 1024 // 100MB
	RequestTimeout      = 30 * time.Second
)

const (
	MaxAuthAttempts = 5
	BlockDuration   = 15 * time.Minute
)

const (
	EndpointRegister  = "/api/register"
	EndpointWebSocket = "/ws/"
	EndpointRoot      = "/"
)

const (
	TimeFormatShort = "15:04:05"
	DurationHour    = "1 hour"
)

const (
	ColorReset  = "\033[0m"
	ColorBold   = "\033[1m"
	ColorDim    = "\033[2m"
	ColorCyan   = "\033[36m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorRed    = "\033[31m"
	ColorPurple = "\033[35m"
)

const (
	RedisKeyPrefix   = "ssrok:session:"
	RedisKeyTTLField = "ttl"
)

const (
	MsgInvalidJSON       = "Invalid JSON"
	MsgMethodNotAllowed  = "Method not allowed"
	MsgInvalidPort       = "Invalid port"
	MsgTunnelNotFound    = "Tunnel not found or expired"
	MsgTunnelNotActive   = "Tunnel not connected"
	MsgRateLimitExceeded = "Rate limit exceeded"
	MsgUsage             = "Usage: ssrok <port>"
	MsgExample           = "Example: ssrok 3000"
)
