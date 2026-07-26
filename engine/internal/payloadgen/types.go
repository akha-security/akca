package payloadgen

import "github.com/akha-security/akca/engine/internal/reflection"

type Payload struct {
	Value                string `json:"value"`
	VulnClass            string `json:"vuln_class"`
	Variant              string `json:"variant"`
	Family               string `json:"family"`
	ExpectedSignal       string `json:"expected_signal"`
	Encoding             string `json:"encoding"`
	Priority             int    `json:"priority"`
	NoiseLevel           string `json:"noise_level"`
	BudgetCost           int    `json:"budget_cost"`
	VerificationStrategy string `json:"verification_strategy"`
	SelectionReason      string `json:"selection_reason"`
	RequiredContext      string `json:"required_context"`
	RiskLevel            string `json:"risk_level"`
	IsControl            bool   `json:"is_control,omitempty"`
	IsNegativeControl    bool   `json:"is_negative_control,omitempty"`
	WAFAdapted           bool   `json:"waf_adapted,omitempty"`
	WAFVendor            string `json:"waf_vendor,omitempty"`
	SemanticKey          string `json:"semantic_key"`
}

type SkipFamily struct {
	Family string `json:"family"`
	Reason string `json:"reason"`
}

type GenerationResult struct {
	EndpointURL string       `json:"endpoint_url"`
	Parameter   string       `json:"parameter"`
	Tech        TechHints    `json:"tech,omitempty"`
	Payloads    []Payload    `json:"payloads"`
	Skipped     []SkipFamily `json:"skipped_families"`
	BudgetUsed  int          `json:"budget_used"`
	BudgetLimit int          `json:"budget_limit"`
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
}

type EventSink func(eventType, message string, payload map[string]interface{}) error
