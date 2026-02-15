package protocol

import "time"

type ConfigRequest struct {
	Port      int    `json:"port"`
	Password  string `json:"password"`
	RateLimit int    `json:"rate_limit"`
}

type ConfigResponse struct {
	UUID      string        `json:"uuid"`
	URL       string        `json:"url"`
	Token     string        `json:"token"`
	ExpiresIn time.Duration `json:"expires_in"`
}

type ClientConfig struct {
	ServerURL string
	LocalPort int
	Password  string
	RateLimit int
}
