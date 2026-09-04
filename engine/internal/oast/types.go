package oast

import (
	"time"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

type Interaction struct {
	Protocol      string    `json:"protocol"`
	UniqueID      string    `json:"unique-id"`
	FullID        string    `json:"full-id"`
	RemoteAddress string    `json:"remote-address"`
	RawRequest    string    `json:"raw-request,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
}

type Correlation struct {
	ScanID           string                   `json:"scan_id"`
	PayloadID        string                   `json:"payload_id"`
	CandidateID      string                   `json:"candidate_id"`
	CorrelationToken string                   `json:"correlation_token"`
	Nonce            string                   `json:"nonce"`
	EndpointURL      string                   `json:"endpoint_url"`
	Parameter        string                   `json:"parameter,omitempty"`
	Location         string                   `json:"location,omitempty"`
	Method           string                   `json:"method,omitempty"`
	VulnClass        string                   `json:"vuln_class,omitempty"`
	FindingID        int64                    `json:"finding_id,omitempty"`
	CallbackURL      string                   `json:"callback_url"`
	RegisteredAt     time.Time                `json:"registered_at"`
	ProbeSentAt      time.Time                `json:"probe_sent_at,omitempty"`
	Payload          string                   `json:"payload,omitempty"`
	Request          httpclient.RequestRecord `json:"request,omitempty"`
}

// ProbeBinding captures the complete identity of one outbound blind probe.
// The callback token is deliberately generated separately from PayloadID so
// repeated payload labels can never overwrite another correlation.
type ProbeBinding struct {
	PayloadID   string `json:"payload_id"`
	CandidateID string `json:"candidate_id"`
	EndpointURL string `json:"endpoint_url"`
	Parameter   string `json:"parameter,omitempty"`
	Location    string `json:"location"`
	VulnClass   string `json:"vuln_class"`
	FindingID   int64  `json:"finding_id,omitempty"`
}

type GeneratedURL struct {
	URL              string `json:"url"`
	Host             string `json:"host,omitempty"`
	PayloadID        string `json:"payload_id"`
	CandidateID      string `json:"candidate_id"`
	CorrelationToken string `json:"correlation_token"`
	Nonce            string `json:"nonce"`
}

type CallbackRecord struct {
	ScanID       string      `json:"scan_id"`
	PayloadID    string      `json:"payload_id"`
	Protocol     string      `json:"protocol"`
	SourceIP     string      `json:"source_ip"`
	Interaction  Interaction `json:"interaction"`
	Correlation  Correlation `json:"correlation"`
	ConfidenceUp bool        `json:"confidence_upgraded"`
	Strength     int         `json:"protocol_strength"`
	ReceivedAt   time.Time   `json:"received_at"`
}

func InteractionStrength(protocol string) int {
	switch protocol {
	case "http", "https":
		return 3
	case "smtp", "ldap":
		return 2
	case "dns":
		return 1
	default:
		return 0
	}
}

type EventSink func(eventType, message string, payload map[string]interface{}) error

type Provider interface {
	Start() error
	Stop() error
	Domain() string
	GenerateURL(payloadID string) (GeneratedURL, error)
	Poll() ([]Interaction, error)
}
