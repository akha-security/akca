package verification

import (
	"time"

	"github.com/akha-security/akca/engine/internal/oast"
	"github.com/akha-security/akca/engine/internal/reflection"
)

type ConfidenceLevel string

const (
	Confirmed         ConfidenceLevel = "Confirmed"
	HighConfidence    ConfidenceLevel = "HighConfidence"
	Potential         ConfidenceLevel = "Potential"
	NeedsManualReview ConfidenceLevel = "NeedsManualReview"
	Suppressed        ConfidenceLevel = "Suppressed"
)

type ProofType string

const (
	ProofNone               ProofType = ""
	ProofDifferentialReplay ProofType = "differential_replay"
	ProofBooleanPair        ProofType = "boolean_pair"
	ProofTiming             ProofType = "timing"
	ProofOAST               ProofType = "oast_callback"
	ProofDOMExecution       ProofType = "dom_execution"
	ProofStateMutation      ProofType = "state_mutation"
	ProofIdentityBoundary   ProofType = "identity_boundary"
	ProofFileRetrieval      ProofType = "file_retrieval"
	ProofRuntimeTrace       ProofType = "runtime_trace"
	ProofPolicyViolation    ProofType = "policy_violation"
	ProofHeaderEvidence     ProofType = "header_evidence"
	ProofContentEvidence    ProofType = "content_evidence"
	ProofConfiguration      ProofType = "configuration_evidence"
	ProofSchemaExposure     ProofType = "schema_exposure"
	ProofProtocolDesync     ProofType = "protocol_desync"
	ProofRequestPolicy      ProofType = "request_policy"
	ProofAnonymousAccess    ProofType = "anonymous_access"
	ProofStoredExecution    ProofType = "stored_execution"
)

type DowngradeReason string

const (
	ReasonWAFBlockPage       DowngradeReason = "waf_block_page"
	ReasonGenericErrorPage   DowngradeReason = "generic_error_page"
	ReasonFrameworkError     DowngradeReason = "framework_error_page"
	ReasonLoginRedirect      DowngradeReason = "login_redirect"
	ReasonSoft404            DowngradeReason = "soft_404"
	ReasonUnstableResponse   DowngradeReason = "unstable_response"
	ReasonSafeTextContainer  DowngradeReason = "safe_text_container"
	ReasonHoneypotParameter  DowngradeReason = "honeypot_parameter"
	ReasonNoPolymorphicMatch DowngradeReason = "polymorphic_mismatch"
	ReasonTimingNoise        DowngradeReason = "timing_noise"
	ReasonBaselineMatch      DowngradeReason = "baseline_indistinguishable"
	ReasonDOMPresenceOnly    DowngradeReason = "dom_presence_without_execution"
	ReasonInsufficientProof  DowngradeReason = "insufficient_class_specific_proof"
	ReasonTypedReplayFailed  DowngradeReason = "typed_replay_failed"
	ReasonNegativeControlHit DowngradeReason = "negative_control_triggered"
	ReasonOASTMismatch       DowngradeReason = "oast_correlation_mismatch"
	ReasonTimingSamples      DowngradeReason = "insufficient_timing_samples"
)

type ResponseSnapshot struct {
	StatusCode  int               `json:"status_code"`
	Body        string            `json:"body"`
	Headers     map[string]string `json:"headers,omitempty"`
	DurationMs  int64             `json:"duration_ms"`
	ContentType string            `json:"content_type,omitempty"`
}

type BaselineKey struct {
	EndpointURL string `json:"endpoint_url"`
	Method      string `json:"method"`
	Parameter   string `json:"parameter"`
}

type BooleanPairProof struct {
	BaselineHash      string `json:"baseline_hash"`
	FirstTrueHash     string `json:"first_true_hash"`
	FirstFalseHash    string `json:"first_false_hash"`
	ReplayTrueHash    string `json:"replay_true_hash"`
	ReplayFalseHash   string `json:"replay_false_hash"`
	SecondTrueHash    string `json:"second_true_hash"`
	SecondFalseHash   string `json:"second_false_hash"`
	SyntaxControlHash string `json:"syntax_control_hash"`
	Orientation       int    `json:"orientation"`
	SameSurface       bool   `json:"same_surface"`
	SyntaxControlOK   bool   `json:"syntax_control_ok"`
}

type Candidate struct {
	ScanID               string                        `json:"scan_id"`
	Title                string                        `json:"title"`
	VulnClass            string                        `json:"vuln_class"`
	EndpointURL          string                        `json:"endpoint_url"`
	Method               string                        `json:"method"`
	Parameter            string                        `json:"parameter"`
	Payload              string                        `json:"payload"`
	Module               string                        `json:"module"`
	Signal               string                        `json:"signal,omitempty"`
	Baseline             ResponseSnapshot              `json:"baseline"`
	Probe                ResponseSnapshot              `json:"probe"`
	Reflection           *reflection.ReflectionProfile `json:"reflection,omitempty"`
	OAST                 *oast.Correlation             `json:"oast,omitempty"`
	StabilityRuns        []ResponseSnapshot            `json:"stability_runs,omitempty"`
	TypedReplayHits      []bool                        `json:"typed_replay_hits,omitempty"`
	PolymorphicHits      []bool                        `json:"polymorphic_hits,omitempty"`
	NegativeControlSet   bool                          `json:"negative_control_set,omitempty"`
	NegativeControlOK    bool                          `json:"negative_control_ok,omitempty"`
	HoneypotCanaries     []string                      `json:"honeypot_canaries,omitempty"`
	HoneypotBodies       []string                      `json:"honeypot_bodies,omitempty"`
	TimingSamples        []int64                       `json:"timing_samples,omitempty"`
	TimingControl        []int64                       `json:"timing_control,omitempty"`
	TimingBaseline       []int64                       `json:"timing_baseline,omitempty"`
	TimingMatchedControl []int64                       `json:"timing_matched_control,omitempty"`
	DOMPresent           bool                          `json:"dom_present"`
	DOMExecuted          bool                          `json:"dom_executed"`
	ExpectedEquivalent   bool                          `json:"expected_equivalent,omitempty"`
	DirectTypedSignal    bool                          `json:"direct_typed_signal,omitempty"`
	BooleanPairProof     *BooleanPairProof             `json:"boolean_pair_proof,omitempty"`
	Observations         []Observation                 `json:"observations,omitempty"`
	ProofPolicyVersion   string                        `json:"proof_policy_version,omitempty"`
	RequestedProofType   ProofType                     `json:"requested_proof_type,omitempty"`
	LearningFP           float64                       `json:"learning_false_positive_rate,omitempty"`
}

type Result struct {
	Confidence        ConfidenceLevel   `json:"confidence"`
	Score             float64           `json:"score"`
	Suppressed        bool              `json:"suppressed"`
	DowngradeReasons  []DowngradeReason `json:"downgrade_reasons,omitempty"`
	UpgradeReasons    []string          `json:"upgrade_reasons,omitempty"`
	BaselineMatch     bool              `json:"baseline_match"`
	SemanticDiff      bool              `json:"semantic_diff"`
	StabilityRatio    float64           `json:"stability_ratio"`
	PolymorphicOK     bool              `json:"polymorphic_ok"`
	OASTConfirmed     bool              `json:"oast_confirmed"`
	TimingConfirmed   bool              `json:"timing_confirmed"`
	TypedReplayRatio  float64           `json:"typed_replay_ratio,omitempty"`
	NegativeControlOK bool              `json:"negative_control_ok,omitempty"`
	BooleanPairProof  *BooleanPairProof `json:"boolean_pair_proof,omitempty"`
	ProofType         ProofType         `json:"proof_type,omitempty"`
	ProofPolicy       string            `json:"proof_policy_version,omitempty"`
	ProofSatisfied    bool              `json:"proof_satisfied"`
	Observations      []Observation     `json:"observations,omitempty"`
	SemanticDelta     SemanticDelta     `json:"semantic_delta"`
	ErrorFingerprint  string            `json:"error_fingerprint,omitempty"`
	VerifiedAt        time.Time         `json:"verified_at"`
}

type EventSink func(eventType, message string, payload map[string]interface{}) error

const DOMXSSCanaryVar = "__akca_xss_confirmed"
