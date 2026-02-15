package session

import (
	"log"
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
	UseTLS       bool
	CreatedAt    time.Time
	ExpiresAt    time.Time
	Conn         *websocket.Conn
	TunnelActive bool
	RequestCount map[string]int
	LastRequest  map[string]time.Time
	mu           sync.RWMutex
}

func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

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

func (s *Session) VerifyToken(token string) bool {
	providedHash := HashSHA256(token)
	return subtleConstantTimeCompare(providedHash, s.TokenHash) == 1
}

func (s *Session) VerifyPassword(password string) bool {
	providedHash := HashSHA256(password)
	return subtleConstantTimeCompare(providedHash, s.PasswordHash) == 1
}

func (s *Session) HasPassword() bool {
	return s.PasswordHash != ""
}

type MemoryStore struct {
	sessions sync.Map
	onExpire func(uuid string)
}

func NewMemoryStore() *MemoryStore {
	store := &MemoryStore{}
	go store.cleanupLoop()
	return store
}

func (st *MemoryStore) OnExpire(fn func(uuid string)) {
	st.onExpire = fn
}

func (st *MemoryStore) Save(session *Session) {
	log.Printf("💾 Saving session to memory: %s", session.UUID)
	st.sessions.Store(session.UUID, session)
}

func (st *MemoryStore) Get(uuid string) (*Session, bool) {
	val, ok := st.sessions.Load(uuid)
	if !ok {
		return nil, false
	}
	session := val.(*Session)
	if session.IsExpired() {
		st.sessions.Delete(uuid)
		if st.onExpire != nil {
			st.onExpire(uuid)
		}
		return nil, false
	}
	return session, true
}

func (st *MemoryStore) Delete(uuid string) {
	val, ok := st.sessions.Load(uuid)
	if ok {
		session := val.(*Session)
		if session.Conn != nil {
			session.Conn.Close()
		}
		session.RequestCount = nil
		session.LastRequest = nil
	}
	st.sessions.Delete(uuid)
}

func (st *MemoryStore) Close() error {
	return nil
}

func (st *MemoryStore) cleanupLoop() {
	ticker := time.NewTicker(constants.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		st.sessions.Range(func(key, value interface{}) bool {
			session := value.(*Session)
			if session.IsExpired() {
				uuid := key.(string)
				if session.Conn != nil {
					session.Conn.Close()
				}
				st.sessions.Delete(key)
				if st.onExpire != nil {
					st.onExpire(uuid)
				}
				log.Printf("🗑 Expired session cleaned up: %s", uuid)
			}
			return true
		})
	}
}
