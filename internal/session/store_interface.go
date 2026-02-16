package session

import "time"

type SessionData struct {
	ID           string
	UUID         string
	Port         int
	PasswordHash string
	TokenHash    string
	RateLimit    int
	UseTLS       bool
	E2EE         bool
	CreatedAt    time.Time
	ExpiresAt    time.Time
	TunnelActive bool
	RequestCount map[string]int
	LastRequest  map[string]time.Time
}

type StoreInterface interface {
	Save(session *Session)
	Get(uuid string) (*Session, bool)
	Delete(uuid string)
	OnExpire(func(uuid string))
	Close() error
}
