package bypass403

import "github.com/akha-security/akca/engine/internal/httpclient"

type TechniqueCategory string

const (
	PathNormalization    TechniqueCategory = "path_normalization"
	EncodedPath          TechniqueCategory = "encoded_path"
	CaseVariant          TechniqueCategory = "case_variant"
	TrailingSlashDot     TechniqueCategory = "trailing_slash_dot"
	MethodChange         TechniqueCategory = "method_change"
	MethodOverrideHeader TechniqueCategory = "method_override_header"
	ForwardedURLHeader   TechniqueCategory = "forwarded_url_header"
	IPTrustHeader        TechniqueCategory = "ip_trust_header"
	ProtocolPortHeader   TechniqueCategory = "protocol_port_header"
	ContentNegotiation   TechniqueCategory = "content_negotiation"
	AuthHeaderPollution  TechniqueCategory = "auth_header_pollution"
	HopByHopStrip        TechniqueCategory = "hop_by_hop_strip"
	JWTBearerAbuse       TechniqueCategory = "jwt_bearer_abuse"
	BasicAuthAbuse       TechniqueCategory = "basic_auth_abuse"
)

// AuthScheme describes the WWW-Authenticate challenge on a protected endpoint.
type AuthScheme struct {
	Kind      string            `json:"kind"` // Basic, Bearer, Digest, Custom
	Raw       string            `json:"raw"`
	Params    map[string]string `json:"params,omitempty"`
	HasBearer bool              `json:"has_bearer"`
	HasBasic  bool              `json:"has_basic"`
}

type Baseline struct {
	URL             string            `json:"url"`
	Method          string            `json:"method"`
	StatusCode      int               `json:"status_code"`
	Body            string            `json:"body"`
	BodyLength      int               `json:"body_length"`
	WWWAuthenticate string            `json:"www_authenticate,omitempty"`
	AuthScheme      AuthScheme        `json:"auth_scheme,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
}

type Attempt struct {
	Category TechniqueCategory `json:"category"`
	Label    string            `json:"label"`
	Method   string            `json:"method"`
	URL      string            `json:"url"`
	Headers  map[string]string `json:"headers,omitempty"`
}

type AttemptResult struct {
	Attempt               Attempt                    `json:"attempt"`
	Baseline              Baseline                   `json:"baseline"`
	Response              httpclient.ResponseRecord  `json:"response"`
	Request               httpclient.RequestRecord   `json:"request"`
	ControlAttempt        *Attempt                   `json:"control_attempt,omitempty"`
	ControlRequest        *httpclient.RequestRecord  `json:"control_request,omitempty"`
	ControlResponse       *httpclient.ResponseRecord `json:"control_response,omitempty"`
	PublicControlRequest  *httpclient.RequestRecord  `json:"public_control_request,omitempty"`
	PublicControlResponse *httpclient.ResponseRecord `json:"public_control_response,omitempty"`
	RecheckRequest        *httpclient.RequestRecord  `json:"recheck_request,omitempty"`
	RecheckResponse       *httpclient.ResponseRecord `json:"recheck_response,omitempty"`
	Succeeded             bool                       `json:"succeeded"`
	Reason                string                     `json:"reason,omitempty"`
}

type EventSink func(eventType, message string, payload map[string]interface{}) error
