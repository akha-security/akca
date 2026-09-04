package notifications

import "time"

type WebhookType string

const (
	WebhookSlack    WebhookType = "slack"
	WebhookDiscord  WebhookType = "discord"
	WebhookTelegram WebhookType = "telegram"
	WebhookGeneric  WebhookType = "generic"
)

// FindingAlert represents the structured finding data sent in notifications.
type FindingAlert struct {
	ScanID      string    `json:"scan_id"`
	FindingID   int64     `json:"finding_id"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"`
	VulnClass   string    `json:"vuln_class"`
	Endpoint    string    `json:"endpoint"`
	Parameter   string    `json:"parameter,omitempty"`
	Confidence  string    `json:"confidence"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
}
