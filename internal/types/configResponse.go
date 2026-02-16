package types

import "time"

type ConfigResponse struct {
	UUID      string        `json:"uuid"`
	URL       string        `json:"url"`
	Token     string        `json:"token"`
	ExpiresIn time.Duration `json:"expires_in"`
}
