package sessionhealer

import "time"

// SessionState represents the state of the active authentication session.
type SessionState string

const (
	StateActive     SessionState = "active"
	StateHealing    SessionState = "healing"
	StateUnverified SessionState = "unverified"
	StateExpired    SessionState = "expired"
)

// LossReason identifies why a session was marked as lost.
type LossReason string

const (
	ReasonHTTP401         LossReason = "http_401_unauthorized"
	ReasonHTTP403         LossReason = "http_403_forbidden"
	ReasonLoginRedirect   LossReason = "login_redirect"
	ReasonTokenExpired    LossReason = "token_expired_json"
	ReasonSessionDeadlock LossReason = "session_deadlock"
)

// SessionCredentials holds active cookies and headers required to maintain authentication.
type SessionCredentials struct {
	Headers map[string]string `json:"headers"`
	Cookies map[string]string `json:"cookies"`
}

// MacroStep represents an individual HTTP request in an authentication macro.
type MacroStep struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body,omitempty"`
	ExtractName string            `json:"extract_name,omitempty"` // e.g. extract "access_token" from JSON
	ExtractType string            `json:"extract_type,omitempty"` // "json" or "cookie" or "header"
}

// HealEvent records a session healing attempt.
type HealEvent struct {
	Timestamp  time.Time  `json:"timestamp"`
	Reason     LossReason `json:"reason"`
	TriggerURL string     `json:"trigger_url"`
	Success    bool       `json:"success"`
	DurationMs int64      `json:"duration_ms"`
}
