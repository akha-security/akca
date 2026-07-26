package models

import "time"

type WAFProfile struct {
	Host                    string   `json:"host"`
	Vendor                  string   `json:"vendor,omitempty"`
	CDN                     string   `json:"cdn,omitempty"`
	HeaderSignatures        []string `json:"header_signatures,omitempty"`
	BodySignatures          []string `json:"body_signatures,omitempty"`
	StatusPatterns          []int    `json:"status_patterns,omitempty"`
	RateLimitDetected       bool     `json:"rate_limit_detected"`
	ChallengePageDetected   bool     `json:"challenge_page_detected"`
	CautiousModeRecommended bool     `json:"cautious_mode_recommended"`
	Confidence              float64  `json:"confidence"`
	DetectedAt              string   `json:"detected_at"`
}

type TechComponent struct {
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`
	Category string `json:"category,omitempty"`
	Source   string `json:"source,omitempty"`
}

type ReconSecurityAudit struct {
	Score         int               `json:"score"`
	PresentCount  int               `json:"present_count"`
	Headers       map[string]string `json:"headers,omitempty"`
	Missing       []string          `json:"missing,omitempty"`
}

type ReconCookie struct {
	Name         string `json:"name"`
	ValuePreview string `json:"value_preview,omitempty"`
	HttpOnly     bool   `json:"http_only"`
	Secure       bool   `json:"secure"`
	SameSite     string `json:"same_site,omitempty"`
}

type TechFingerprint struct {
	Host            string              `json:"host"`
	BackendLanguage string              `json:"backend_language,omitempty"`
	Framework       string              `json:"framework,omitempty"`
	Database        string              `json:"database,omitempty"`
	ServerCDN       string              `json:"server_cdn,omitempty"`
	JSFramework     string              `json:"js_framework,omitempty"`
	Hints           []string            `json:"hints,omitempty"`
	DetectedAt      string              `json:"detected_at"`
	HTTPStatus      int                 `json:"http_status,omitempty"`
	PageTitle       string              `json:"page_title,omitempty"`
	MetaGenerator   string              `json:"meta_generator,omitempty"`
	Components      []TechComponent     `json:"components,omitempty"`
	ResponseHeaders map[string]string   `json:"response_headers,omitempty"`
	SecurityHeaders ReconSecurityAudit  `json:"security_headers,omitempty"`
	Cookies         []ReconCookie       `json:"cookies,omitempty"`
	TLSHints        []string            `json:"tls_hints,omitempty"`
	ContentType     string              `json:"content_type,omitempty"`
}

type EndpointIntelligence struct {
	URL                 string   `json:"url"`
	Method              string   `json:"method"`
	EndpointType        string   `json:"endpoint_type"`
	AuthRequired        bool     `json:"auth_required"`
	StateChanging       bool     `json:"state_changing"`
	ContentType         string   `json:"content_type,omitempty"`
	RiskTags            []string `json:"risk_tags,omitempty"`
	RecommendedModules  []string `json:"recommended_modules,omitempty"`
	WAFProfile          *WAFProfile       `json:"waf_profile,omitempty"`
	TechFingerprint     *TechFingerprint  `json:"tech_fingerprint,omitempty"`
}

type PluginManifest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Version     string `json:"version"`
}

type SkipReason struct {
	Module   string `json:"module"`
	Reason   string `json:"reason"`
	Endpoint string `json:"endpoint,omitempty"`
}

type DashboardMetric struct {
	ScanID    string         `json:"scan_id"`
	Timestamp string         `json:"ts"`
	Counters  map[string]int `json:"counters"`
}

func NowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}
