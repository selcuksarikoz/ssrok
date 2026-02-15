package security

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ConnectionLimiter tracks connections per IP
type ConnectionLimiter struct {
	mu          sync.RWMutex
	connections map[string]int
	maxConn     int
}

// NewConnectionLimiter creates a new limiter
func NewConnectionLimiter(maxConn int) *ConnectionLimiter {
	return &ConnectionLimiter{
		connections: make(map[string]int),
		maxConn:     maxConn,
	}
}

// TryConnect attempts to register a new connection
func (cl *ConnectionLimiter) TryConnect(ip string) bool {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if cl.connections[ip] >= cl.maxConn {
		return false
	}
	cl.connections[ip]++
	return true
}

// Disconnect decrements connection count
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

// GetClientIP extracts client IP from request
func GetClientIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		return strings.Split(xff, ",")[0]
	}

	xri := r.Header.Get("X-Real-Ip")
	if xri != "" {
		return xri
	}

	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

// BruteForceProtector prevents password brute force
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

// NewBruteForceProtector creates a new protector
func NewBruteForceProtector(maxAttempts int, blockDuration time.Duration) *BruteForceProtector {
	bf := &BruteForceProtector{
		attempts:      make(map[string]*ipAttempts),
		maxAttempts:   maxAttempts,
		blockDuration: blockDuration,
	}
	go bf.cleanup()
	return bf
}

// Check returns true if IP is allowed to attempt
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
		// Unblock
		attempts.count = 0
		attempts.blockedAt = nil
	}

	return attempts.count < bf.maxAttempts
}

// RecordFailure records a failed attempt
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

// RecordSuccess resets attempts on success
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
