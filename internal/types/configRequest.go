package types

import "time"

type ConfigRequest struct {
	Port      int           `json:"port"`
	Password  string        `json:"password"`
	RateLimit int           `json:"rate_limit"`
	UseTLS    bool          `json:"use_tls"`
	ExpiresIn time.Duration `json:"expires_in,omitempty"`
}
