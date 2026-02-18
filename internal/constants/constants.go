package constants

import (
	"net/http"
	"time"
)

const (
	DefaultHost = "localhost"
	DefaultPort = "80"
)

const (
	AppName           = "ssrok"
	DefaultTargetHost = "localhost"
)

var (
	StandardWebPorts = map[string]bool{
		"80":  true,
		"443": true,
	}
)

var (
	// DefaultServerURL can be overwritten at build time using -ldflags
	DefaultServerURL = "http://localhost"

	// Version can be overwritten at build time using -ldflags
	Version = "0.1.12"

	// VersionCheckURL is the URL to check for updates
	VersionCheckURL = "https://raw.githubusercontent.com/selcuksarikoz/ssrok/main/version.json"
)

const (
	MinPort            = 1
	MaxPort            = 65535
	BufferSize         = 131072   // 128KB
	WSBufferSize       = 131072   // 128KB
	MaxWSMessageSize   = 16777216 // 16MB
	WSHandshakeTimeout = 30 * time.Second
	CopyBufferSize     = 524288 // 512KB
	DialTimeout        = 5 * time.Second
	CleanupInterval    = 30 * time.Second
	StreamTypeProxy    = 0x00
	StreamTypeLog      = 0x01
	StreamTypeStats    = 0x02
	WSCompression      = false
)

const (
	YamuxMaxStreamWindowSize = 4 * 1024 * 1024
	YamuxAcceptBacklog       = 512
	YamuxEnableKeepAlive     = true
	YamuxKeepAliveInterval   = 30 * time.Second
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
	DefaultRateLimit    = 0
	RateLimitWindow     = time.Minute
	UnlimitedRateLimit  = 0
	MaxConnectionsPerIP = 10
	MaxBodySize         = 100 * 1024 * 1024 // 100MB
	MaxConfigBodySize   = 1024              // 1KB for config/register
	MaxAuthBodySize     = 4096              // 4KB for login forms
	MaxLogBufferSize    = 1024 * 1024       // 1MB per request/response for logging
	RequestTimeout      = 30 * time.Second
)

const (
	MaxAuthAttempts = 5
	BlockDuration   = 15 * time.Minute
)

const (
	StreamingThresholdSize   = 10 * 1024 * 1024 // 10MB - above this consider streaming
	RequestSampleRate        = 10               // Log 1 in every N requests for high-volume
	RequestFloodingThreshold = 100              // Requests per minute to trigger flooding detection
	HighVolumeWindow         = time.Minute
	MaxAuditLogsPerMinute    = 1000              // Limit audit logs to prevent disk flooding
	MaxAuditLogFileSize      = 100 * 1024 * 1024 // 100MB per log file
	MaxAuditLogRetentionDays = 7                 // Keep logs for 7 days
	MinDiskSpaceRequired     = 500 * 1024 * 1024 // 500MB minimum free space
	AuditBufferSize          = 100               // Buffer 100 logs before writing to disk
	AuditFlushInterval       = 5 * time.Second   // Flush buffer every 5 seconds
	StaticAssetLogThreshold  = 50                // Log static assets after this many requests
	StaticAssetSampleRate    = 10                // Sample 1 in N static asset requests
	PendingLogBufferSize     = 100               // Pending logs buffer for tunnel
	MaxHeaderBytes           = 1 << 20           // 1MB max headers
	ServerShutdownTimeout    = 5 * time.Second   // Graceful shutdown timeout
	ReadHeaderTimeout        = 10 * time.Second  // Timeout for reading headers
	ProtocolDetectionTimeout = 2 * time.Second   // Timeout for protocol detection
)

const (
	EndpointRoot      = "/"
	EndpointRegister  = "/register"
	EndpointWebSocket = "/ws/"
	CookieUUIDContext = "uuid"
)

const (
	MinTokenLength   = 32
	AuthRetryTicker  = 5 * time.Minute
	DefaultUUIDRegex = `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`
)

var (
	TrustedCIDRs = []string{
		"127.0.0.0/8",
		"::1/128",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}
)

var (
	IgnoredLogPrefixes = []string{
		"/_next",
		"/webpack",
		"/vite",
		"/__webpack_hmr",
		"/@vite",
		"/__vite_ping",
		"/@fs",
		"/browser-sync",
		"/sockjs-node",
		"/__nextjs",
		"/hot-update",
		"/__HMR",
		"/__ws",
		"/_hot",
	}

	StaticAssetExtensions = []string{
		".css",
		".js",
		".png",
		".jpg",
		".jpeg",
		".gif",
		".svg",
		".ico",
		".woff",
		".woff2",
		".ttf",
		".eot",
		".otf",
		".webp",
		".map",
		".json",
	}
)

const (
	DashboardHost            = "localhost"
	DashboardPort            = 31331
	DashboardMaxLogs         = 1000
	DashboardWSReadBuffer    = 1024
	DashboardWSWriteBuffer   = 1024
	DashboardShutdownTimeout = 5 * time.Second
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
	MsgExample           = "Example: ssrok 3000"
	MsgUsage             = "Usage: ssrok <port> or ssrok <ip>:<port>"
)

const (
	SymbolSuccess  = "✅"
	SymbolError    = "❌"
	SymbolRedirect = "🔄"
	SymbolIncoming = "📥"
	SymbolAuth     = "✨"
	SymbolLock     = "🔐"
	SymbolWarning  = "⛔"
	SymbolView     = "👤"
	SymbolNotify   = "🔔"
)
