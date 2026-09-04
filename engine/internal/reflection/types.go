package reflection

// RequestTemplate is the canonical replay shape used by active probes.  It is
// deliberately transport-agnostic: mutation changes one injection surface
// while preserving the discovered method, URL, body and ambient headers.
type RequestTemplate struct {
	Method      string            `json:"method,omitempty"`
	URL         string            `json:"url,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
}

// MutatedRequest is a fully materialized HTTP request ready for the transport.
type MutatedRequest struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
}

type ContextType string

const (
	ContextHTML       ContextType = "html_body"
	ContextAttribute  ContextType = "attribute"
	ContextJavaScript ContextType = "javascript"
	ContextCSS        ContextType = "css"
	ContextURL        ContextType = "url"
	ContextJSON       ContextType = "json"
	ContextXML        ContextType = "xml"
	ContextComment    ContextType = "comment"
	ContextUnknown    ContextType = "unknown"
)

type ReflectionKind string

const (
	ReflectionRaw     ReflectionKind = "raw"
	ReflectionEncoded ReflectionKind = "encoded"
	ReflectionPartial ReflectionKind = "partial"
	ReflectionRemoved ReflectionKind = "removed"
)

type ReflectionProfile struct {
	ScanID            string         `json:"scan_id"`
	EndpointURL       string         `json:"endpoint_url"`
	Method            string         `json:"method"`
	Parameter         string         `json:"parameter"`
	ParameterLocation string         `json:"parameter_location"`
	CanaryID          string         `json:"canary_id"`
	CanaryValue       string         `json:"canary_value"`
	ReflectionKind    ReflectionKind `json:"reflection_kind"`
	Context           ContextType    `json:"context"`
	QuoteType         string         `json:"quote_type"`
	AvailableChars    []string       `json:"available_chars,omitempty"`
	BlockedChars      []string       `json:"blocked_chars,omitempty"`
	Stable            bool           `json:"stable"`
	HoneypotSuspected bool           `json:"honeypot_suspected"`
	ContentType       string         `json:"content_type,omitempty"`
	Confidence        float64        `json:"confidence"`
}

type EventSink func(eventType, message string, payload map[string]interface{}) error
