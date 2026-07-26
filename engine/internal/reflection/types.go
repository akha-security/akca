package reflection

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
