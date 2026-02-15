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
	CreatedAt    time.Time
	ExpiresAt    time.Time
	TunnelActive bool
}

type StoreInterface interface {
	Save(session *Session)
	Get(uuid string) (*Session, bool)
	Delete(uuid string)
	OnExpire(func(uuid string))
	Close() error
}
