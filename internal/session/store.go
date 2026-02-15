package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"ssrok/internal/constants"
	"ssrok/internal/utils"
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
	providedHash := utils.HashSHA256(token)
	return subtle.ConstantTimeCompare([]byte(providedHash), []byte(s.TokenHash)) == 1
}

func (s *Session) VerifyPassword(password string) bool {
	if s.PasswordHash == "" {
		return true
	}
	providedHash := utils.HashSHA256(password)
	return subtle.ConstantTimeCompare([]byte(providedHash), []byte(s.PasswordHash)) == 1
}

func (s *Session) HasPassword() bool {
	return s.PasswordHash != ""
}

type Store struct {
	sessions sync.Map
	OnExpire func(uuid string)
}

func NewStore() *Store {
	store := &Store{}
	go store.cleanupLoop()
	return store
}

func (st *Store) Save(session *Session) {
	st.sessions.Store(session.UUID, session)
}

func (st *Store) Get(uuid string) (*Session, bool) {
	val, ok := st.sessions.Load(uuid)
	if !ok {
		return nil, false
	}
	session := val.(*Session)
	if session.IsExpired() {
		st.sessions.Delete(uuid)
		if st.OnExpire != nil {
			st.OnExpire(uuid)
		}
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
				uuid := key.(string)
				if session.Conn != nil {
					session.Conn.Close()
				}
				st.sessions.Delete(key)
				if st.OnExpire != nil {
					st.OnExpire(uuid)
				}
				log.Printf("🗑 Expired session cleaned up: %s", uuid)
			}
			return true
		})
	}
}

var (
	cookieSigningKey []byte
	signingKeyOnce   sync.Once
)

func getCookieSigningKey() []byte {
	signingKeyOnce.Do(func() {
		cookieSigningKey = make([]byte, 32)
		if _, err := rand.Read(cookieSigningKey); err != nil {
			panic("failed to generate cookie signing key: " + err.Error())
		}
	})
	return cookieSigningKey
}

func SignCookieValue(uuid string) string {
	mac := hmac.New(sha256.New, getCookieSigningKey())
	mac.Write([]byte(uuid))
	sig := hex.EncodeToString(mac.Sum(nil))
	return uuid + ":" + sig
}

func VerifyCookieValue(cookieValue string) (string, bool) {
	parts := splitCookieValue(cookieValue)
	if parts == nil {
		return "", false
	}
	uuid := parts[0]
	providedSig := parts[1]

	mac := hmac.New(sha256.New, getCookieSigningKey())
	mac.Write([]byte(uuid))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if subtle.ConstantTimeCompare([]byte(providedSig), []byte(expectedSig)) != 1 {
		return "", false
	}
	return uuid, true
}

func splitCookieValue(value string) []string {
	idx := -1
	for i := len(value) - 1; i >= 0; i-- {
		if value[i] == ':' {
			idx = i
			break
		}
	}
	if idx <= 0 || idx >= len(value)-1 {
		return nil
	}
	return []string{value[:idx], value[idx+1:]}
}

func GenerateCSRFToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate CSRF token: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func SignCSRFToken(token string) string {
	mac := hmac.New(sha256.New, getCookieSigningKey())
	mac.Write([]byte(token))
	sig := hex.EncodeToString(mac.Sum(nil))
	return token + ":" + sig
}

func VerifyCSRFToken(signedToken string) bool {
	parts := splitCookieValue(signedToken)
	if parts == nil {
		return false
	}
	token := parts[0]
	providedSig := parts[1]

	mac := hmac.New(sha256.New, getCookieSigningKey())
	mac.Write([]byte(token))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	return subtle.ConstantTimeCompare([]byte(providedSig), []byte(expectedSig)) == 1
}
