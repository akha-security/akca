package payloadgen

import "github.com/akha-security/akca/engine/internal/reflection"

type Technique string

const (
	TechniqueBaseline            Technique = "baseline"
	TechniqueDifferential        Technique = "differential"
	TechniqueTiming              Technique = "timing"
	TechniqueOAST                Technique = "oast"
	TechniqueContext             Technique = "context"
	TechniqueWAFMutation         Technique = "waf_mutation"
	TechniqueSyntaxProbe         Technique = "syntax_probe"
	TechniqueBooleanDifferential Technique = "boolean_differential"
	TechniqueTimingDifferential  Technique = "timing_differential"
	TechniqueAuthBypass          Technique = "auth_bypass"
	TechniqueContextBreakout     Technique = "context_breakout"
	TechniquePolyglot            Technique = "polyglot"
)

type ProbeRole string

const (
	ProbeRoleBaseline     ProbeRole = "baseline"
	ProbeRolePositive     ProbeRole = "positive"
	ProbeRoleNegative     ProbeRole = "negative"
	ProbeRoleConfirmation ProbeRole = "confirmation"
	ProbeRoleOAST         ProbeRole = "oast"
)

type MutationSpec struct {
	Layer     string `json:"layer"`
	Technique string `json:"technique"`
}

type Payload struct {
	Value                string         `json:"value"`
	VulnClass            string         `json:"vuln_class"`
	Variant              string         `json:"variant"`
	Family               string         `json:"family"`
	ExpectedSignal       string         `json:"expected_signal"`
	Encoding             string         `json:"encoding"`
	Priority             int            `json:"priority"`
	NoiseLevel           string         `json:"noise_level"`
	BudgetCost           int            `json:"budget_cost"`
	VerificationStrategy string         `json:"verification_strategy"`
	SelectionReason      string         `json:"selection_reason"`
	RequiredContext      string         `json:"required_context"`
	RiskLevel            string         `json:"risk_level"`
	IsControl            bool           `json:"is_control,omitempty"`
	IsNegativeControl    bool           `json:"is_negative_control,omitempty"`
	WAFAdapted           bool           `json:"waf_adapted,omitempty"`
	WAFVendor            string         `json:"waf_vendor,omitempty"`
	SemanticKey          string         `json:"semantic_key"`
	Technique            Technique      `json:"technique,omitempty"`
	ProbeRole            ProbeRole      `json:"probe_role,omitempty"`
	PairID               string         `json:"pair_id,omitempty"`
	ControlFor           string         `json:"control_for,omitempty"`
	RequiresOAST         bool           `json:"requires_oast,omitempty"`
	EstimatedRequests    int            `json:"estimated_requests,omitempty"`
	Mutations            []MutationSpec `json:"mutations,omitempty"`
	TransportEncoding    string         `json:"transport_encoding,omitempty"`
}

type SkipFamily struct {
	Family string `json:"family"`
	Reason string `json:"reason"`
}

type ProbeStep struct {
	Role              ProbeRole `json:"role"`
	Payload           Payload   `json:"payload"`
	ExpectedSignal    string    `json:"expected_signal,omitempty"`
	EstimatedRequests int       `json:"estimated_requests,omitempty"`
}

type TestCase struct {
	ID                string      `json:"id"`
	VulnClass         string      `json:"vuln_class"`
	Technique         Technique   `json:"technique"`
	ProbeRole         ProbeRole   `json:"probe_role,omitempty"`
	Steps             []ProbeStep `json:"steps,omitempty"`
	Payloads          []Payload   `json:"payloads"`
	EstimatedRequests int         `json:"estimated_requests"`
	ShadowOnly        bool        `json:"shadow_only,omitempty"`
}

type ShadowComparison struct {
	LegacyPayloads     int `json:"legacy_payloads"`
	TestCases          int `json:"test_cases"`
	LegacyBudget       int `json:"legacy_budget"`
	EstimatedRequests  int `json:"estimated_requests"`
	SQLiLegacyPayloads int `json:"sqli_legacy_payloads"`
	SQLiTestCases      int `json:"sqli_test_cases"`
	OrphanControls     int `json:"orphan_controls"`
}

type GenerationResult struct {
	EndpointURL       string           `json:"endpoint_url"`
	Parameter         string           `json:"parameter"`
	Tech              TechHints        `json:"tech,omitempty"`
	Payloads          []Payload        `json:"payloads"`
	TestCases         []TestCase       `json:"test_cases,omitempty"`
	EstimatedRequests int              `json:"estimated_requests,omitempty"`
	Shadow            ShadowComparison `json:"shadow_comparison,omitempty"`
	Skipped           []SkipFamily     `json:"skipped_families"`
	BudgetUsed        int              `json:"budget_used"`
	BudgetLimit       int              `json:"budget_limit"`
}

type LearningProfile struct {
	Worked        []string `json:"worked"`
	Blocked       []string `json:"blocked"`
	Noisy         []string `json:"noisy"`
	FalsePositive []string `json:"false_positive"`
}

type Input struct {
	Profile reflection.ReflectionProfile
	Tech    TechHints
	WAF     WAFHints
	Budget  int
	Learn   LearningProfile
}

type TechHints struct {
	BackendLanguage string
	Framework       string
	Database        string
}

type WAFHints struct {
	Vendor                  string
	CautiousModeRecommended bool
	AllowEvasion            bool
	PreferredTechniques     []string
	BlockedChars            []string
	AllowedChars            []string
}

type EventSink func(eventType, message string, payload map[string]interface{}) error
