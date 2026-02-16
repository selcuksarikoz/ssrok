package utils

var HopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailers":            true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

var SensitiveRequestHeaders = map[string]bool{
	"Cookie": true,
}

var DangerousResponseHeaders = map[string]bool{
	"Set-Cookie":                true,
	"Strict-Transport-Security": true,
	"Content-Security-Policy":   true,
	"X-Frame-Options":           true,
	"X-Xss-Protection":          true,
	"X-Content-Type-Options":    true,
}

var HopByHopHeadersNames = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}
