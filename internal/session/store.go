package session

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"ssrok/internal/constants"
)

type Session struct {
	ID           string
	UUID         string
	Port         int
	PasswordHash string
	TokenHash    string
	RateLimit    int
	CreatedAt    time.Time
	ExpiresAt    time.Time
	Conn         *websocket.Conn
	TunnelActive bool
	RequestCount map[string]int
	LastRequest  map[string]time.Time
	mu           sync.RWMutex
}

// IsExpired returns true if session has expired
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// CheckRateLimit returns true if IP is within rate limit
func (s *Session) CheckRateLimit(ip string) bool {
	if s.RateLimit == constants.UnlimitedRateLimit {
		return true
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	lastReq, exists := s.LastRequest[ip]

	if !exists || now.Sub(lastReq) > constants.RateLimitWindow {
		s.RequestCount[ip] = 0
	}

	s.LastRequest[ip] = now
	s.RequestCount[ip]++

	return s.RequestCount[ip] <= s.RateLimit
}

// VerifyToken returns true if token matches
func (s *Session) VerifyToken(token string) bool {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:]) == s.TokenHash
}

// VerifyPassword returns true if password matches (or no password set)
func (s *Session) VerifyPassword(password string) bool {
	if s.PasswordHash == "" {
		return true
	}
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:]) == s.PasswordHash
}

// HasPassword returns true if session has password protection
func (s *Session) HasPassword() bool {
	return s.PasswordHash != ""
}

type Store struct {
	sessions sync.Map
}

// NewStore creates a new session store with cleanup goroutine
func NewStore() *Store {
	store := &Store{}
	go store.cleanupLoop()
	return store
}

func (st *Store) Save(session *Session) {
	st.sessions.Store(session.UUID, session)
}

// Get retrieves session by UUID, returns nil if expired
func (st *Store) Get(uuid string) (*Session, bool) {
	val, ok := st.sessions.Load(uuid)
	if !ok {
		return nil, false
	}
	session := val.(*Session)
	if session.IsExpired() {
		st.sessions.Delete(uuid)
		return nil, false
	}
	return session, true
}

func (st *Store) Delete(uuid string) {
	st.sessions.Delete(uuid)
}

func (st *Store) cleanupLoop() {
	ticker := time.NewTicker(constants.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		st.sessions.Range(func(key, value interface{}) bool {
			session := value.(*Session)
			if session.IsExpired() {
				if session.Conn != nil {
					session.Conn.Close()
				}
				st.sessions.Delete(key)
			}
			return true
		})
	}
}

// Hash returns SHA256 hash of input
func Hash(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}
