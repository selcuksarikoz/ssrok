package types

import "time"

type ConfigResponse struct {
	UUID      string        `json:"uuid"`
	URL       string        `json:"url"`
	Token     string        `json:"token"`
	E2EE      bool          `json:"e2ee"`
	ExpiresIn time.Duration `json:"expires_in"`
}
