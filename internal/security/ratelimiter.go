package security

import (
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type ConnectionLimiter struct {
	mu          sync.RWMutex
	connections map[string]int
	maxConn     int
}

func NewConnectionLimiter(maxConn int) *ConnectionLimiter {
	return &ConnectionLimiter{
		connections: make(map[string]int),
		maxConn:     maxConn,
	}
}

func (cl *ConnectionLimiter) TryConnect(ip string) bool {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if cl.connections[ip] >= cl.maxConn {
		return false
	}
	cl.connections[ip]++
	return true
}

func (cl *ConnectionLimiter) Disconnect(ip string) {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if cl.connections[ip] > 0 {
		cl.connections[ip]--
		if cl.connections[ip] == 0 {
			delete(cl.connections, ip)
		}
	}
}

var (
	trustedProxies []*net.IPNet
	proxyOnce      sync.Once
)

func initTrustedProxies() {
	proxyOnce.Do(func() {
		defaultCIDRs := []string{"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
		if env := os.Getenv("SSROK_TRUSTED_PROXIES"); env != "" {
			defaultCIDRs = strings.Split(env, ",")
		}
		for _, cidr := range defaultCIDRs {
			cidr = strings.TrimSpace(cidr)
			_, network, err := net.ParseCIDR(cidr)
			if err == nil {
				trustedProxies = append(trustedProxies, network)
			}
		}
	})
}

func isTrustedProxy(ip string) bool {
	initTrustedProxies()
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, network := range trustedProxies {
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}

// GetClientIP extracts client IP, only trusting proxy headers from trusted sources.
func GetClientIP(r *http.Request) string {
	directIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if directIP == "" {
		directIP = r.RemoteAddr
	}

	if isTrustedProxy(directIP) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			clientIP := strings.TrimSpace(strings.Split(xff, ",")[0])
			if net.ParseIP(clientIP) != nil {
				return clientIP
			}
		}
		if xri := r.Header.Get("X-Real-Ip"); xri != "" {
			xri = strings.TrimSpace(xri)
			if net.ParseIP(xri) != nil {
				return xri
			}
		}
	}

	return directIP
}

type BruteForceProtector struct {
	mu            sync.RWMutex
	attempts      map[string]*ipAttempts
	maxAttempts   int
	blockDuration time.Duration
}

type ipAttempts struct {
	count     int
	blockedAt *time.Time
}

func NewBruteForceProtector(maxAttempts int, blockDuration time.Duration) *BruteForceProtector {
	bf := &BruteForceProtector{
		attempts:      make(map[string]*ipAttempts),
		maxAttempts:   maxAttempts,
		blockDuration: blockDuration,
	}
	go bf.cleanup()
	return bf
}

func (bf *BruteForceProtector) Check(ip string) bool {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	attempts, exists := bf.attempts[ip]
	if !exists {
		return true
	}

	if attempts.blockedAt != nil {
		if time.Since(*attempts.blockedAt) < bf.blockDuration {
			return false
		}
		attempts.count = 0
		attempts.blockedAt = nil
	}

	return attempts.count < bf.maxAttempts
}

func (bf *BruteForceProtector) RecordFailure(ip string) {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	attempts, exists := bf.attempts[ip]
	if !exists {
		attempts = &ipAttempts{count: 0}
		bf.attempts[ip] = attempts
	}

	attempts.count++
	if attempts.count >= bf.maxAttempts {
		now := time.Now()
		attempts.blockedAt = &now
	}
}

func (bf *BruteForceProtector) RecordSuccess(ip string) {
	bf.mu.Lock()
	defer bf.mu.Unlock()
	delete(bf.attempts, ip)
}

func (bf *BruteForceProtector) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		bf.mu.Lock()
		for ip, attempts := range bf.attempts {
			if attempts.blockedAt != nil && time.Since(*attempts.blockedAt) > bf.blockDuration {
				delete(bf.attempts, ip)
			}
		}
		bf.mu.Unlock()
	}
}
