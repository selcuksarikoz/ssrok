package types

import "time"

type ConfigRequest struct {
	Port      int           `json:"port"`
	Password  string        `json:"password"`
	RateLimit int           `json:"rate_limit"`
	UseTLS    bool          `json:"use_tls"`
	E2EE      bool          `json:"e2ee"`
	ExpiresIn time.Duration `json:"expires_in,omitempty"`
}
