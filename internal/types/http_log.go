package types

import "time"

type RequestDetails struct {
	Headers     map[string][]string `json:"headers"`
	Body        string              `json:"body"`
	QueryParams map[string][]string `json:"query_params"`
}

type ResponseDetails struct {
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
}

type HTTPLog struct {
	ID         string          `json:"id"`
	Method     string          `json:"method"`
	Path       string          `json:"path"`
	StatusCode int             `json:"status_code"`
	Duration   time.Duration   `json:"duration"`
	Timestamp  time.Time       `json:"timestamp"`
	UserAgent  string          `json:"user_agent"`
	ClientIP   string          `json:"client_ip"`
	Request    RequestDetails  `json:"request"`
	Response   ResponseDetails `json:"response"`
}

type SecurityEvent struct {
	ID        string    `json:"id"`
	EventType string    `json:"event_type"`
	IP        string    `json:"ip"`
	Details   string    `json:"details"`
	Severity  string    `json:"severity"`
	Timestamp time.Time `json:"timestamp"`
}
