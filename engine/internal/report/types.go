package report

import (
	"time"

	"github.com/akha-security/akca/engine/internal/storage"
)

type TemplateKind string

const (
	TemplateHackerOne TemplateKind = "hackerone"
	TemplateBugcrowd  TemplateKind = "bugcrowd"
	TemplateInternal  TemplateKind = "internal"
	TemplateExecutive TemplateKind = "executive"
	TemplateAppendix  TemplateKind = "appendix"
)

type Format string

const (
	FormatHTML     Format = "html"
	FormatJSON     Format = "json"
	FormatCSV      Format = "csv"
	FormatMarkdown Format = "markdown"
	FormatSARIF    Format = "sarif"
)

type Progress struct {
	Format      Format       `json:"format"`
	Section     string       `json:"section"`
	Percent     int          `json:"percent"`
	ETA         string       `json:"eta,omitempty"`
	RowsWritten int          `json:"rows_written,omitempty"`
	Template    TemplateKind `json:"template,omitempty"`
}

type ProgressFunc func(Progress)

type Options struct {
	ScanID      string
	Template    TemplateKind
	Format      Format
	Partial     bool
	FindingIDs  []int64
	Severities  []string
	Confidences []string
	VulnClasses []string
	SearchQuery string
	Redact      bool
	CSVColumns  []string
}

type ScopeSection struct {
	Targets    []string `json:"targets"`
	InScope    []string `json:"in_scope,omitempty"`
	OutOfScope []string `json:"out_of_scope,omitempty"`
	ScanID     string   `json:"scan_id"`
}

type HTTPEvidence struct {
	Module           string                                  `json:"module,omitempty"`
	Signal           string                                  `json:"signal,omitempty"`
	Payload          string                                  `json:"payload,omitempty"`
	Parameter        string                                  `json:"parameter,omitempty"`
	Location         string                                  `json:"location,omitempty"`
	ResponseMarkers  []string                                `json:"response_markers,omitempty"`
	ProofSummary     string                                  `json:"proof_summary,omitempty"`
	Method           string                                  `json:"method,omitempty"`
	URL              string                                  `json:"url,omitempty"`
	StatusCode       int                                     `json:"status_code,omitempty"`
	DurationMs       int64                                   `json:"duration_ms,omitempty"`
	OASTURL          string                                  `json:"oast_url,omitempty"`
	RawRequest       string                                  `json:"raw_request,omitempty"`
	RawResponse      string                                  `json:"raw_response,omitempty"`
	CurlCommand      string                                  `json:"curl_command,omitempty"`
	RespBody         string                                  `json:"resp_body,omitempty"`
	ConfidenceScore  float64                                 `json:"confidence_score,omitempty"`
	ProofType        string                                  `json:"proof_type,omitempty"`
	ProofPolicy      string                                  `json:"proof_policy_version,omitempty"`
	ProofSatisfied   bool                                    `json:"proof_satisfied"`
	DowngradeReasons []string                                `json:"downgrade_reasons,omitempty"`
	UpgradeReasons   []string                                `json:"upgrade_reasons,omitempty"`
	SemanticDelta    map[string]interface{}                  `json:"semantic_delta,omitempty"`
	Observations     []storage.VerificationObservationRecord `json:"observations,omitempty"`
	Baseline         []storage.VerificationObservationRecord `json:"baseline_observations,omitempty"`
	Probes           []storage.VerificationObservationRecord `json:"probe_observations,omitempty"`
	Controls         []storage.VerificationObservationRecord `json:"control_observations,omitempty"`
	Replays          []storage.VerificationObservationRecord `json:"replay_observations,omitempty"`
	State            []storage.VerificationObservationRecord `json:"state_observations,omitempty"`
	Identity         []storage.VerificationObservationRecord `json:"identity_observations,omitempty"`
	ExternalProof    []storage.VerificationObservationRecord `json:"external_proof_observations,omitempty"`
	ScreenshotRef    string                                  `json:"screenshot_ref,omitempty"`
	DOMSnapshotRef   string                                  `json:"dom_snapshot_ref,omitempty"`
}

type FindingEntry struct {
	ID                int64        `json:"id"`
	Title             string       `json:"title"`
	Summary           string       `json:"summary"`
	Description       string       `json:"description"`
	Severity          string       `json:"severity"`
	Confidence        string       `json:"confidence"`
	ConfidenceScore   float64      `json:"confidence_score"`
	ConfidenceExplain string       `json:"confidence_explanation"`
	VulnClass         string       `json:"vuln_class"`
	EndpointURL       string       `json:"endpoint_url"`
	Parameter         string       `json:"parameter"`
	ReproductionSteps []string     `json:"reproduction_steps"`
	Impact            string       `json:"impact"`
	Remediation       string       `json:"remediation"`
	EvidenceSummary   string       `json:"evidence_summary"`
	HTTPEvidence      HTTPEvidence `json:"http_evidence"`
	AffectedInstances []string     `json:"affected_instances"`
	RootCause         string       `json:"root_cause,omitempty"`
	ReplayCommand     string       `json:"replay_command,omitempty"`
}

type ManualLeadEntry struct {
	Finding             FindingEntry `json:"finding"`
	AutomaticallyProven bool         `json:"automatically_proven"`
	SubmissionReady     bool         `json:"bug_bounty_submission_ready"`
	Warning             string       `json:"warning"`
}

type APIKeySection struct {
	Service     string `json:"service"`
	Status      string `json:"status"`
	Risk        string `json:"risk_assessment"`
	Remediation string `json:"remediation"`
	Details     string `json:"details_redacted"`
}

type TrafficEntry struct {
	Method      string `json:"method"`
	URL         string `json:"url"`
	StatusCode  int    `json:"status_code"`
	DurationMs  int64  `json:"duration_ms"`
	RawRequest  string `json:"raw_request"`
	RawResponse string `json:"raw_response"`
}

type Document struct {
	SchemaVersion     string                       `json:"schema_version"`
	GeneratedAt       time.Time                    `json:"generated_at"`
	Template          TemplateKind                 `json:"template"`
	Format            Format                       `json:"format"`
	Partial           bool                         `json:"partial"`
	Title             string                       `json:"title"`
	Summary           string                       `json:"summary"`
	Scope             ScopeSection                 `json:"scope"`
	Metrics           storage.DashboardMetrics     `json:"metrics"`
	Findings          []FindingEntry               `json:"findings,omitempty"`
	ManualLeads       []ManualLeadEntry            `json:"manual_leads,omitempty"`
	RootCauseGroups   []storage.FindingGroupRecord `json:"root_cause_groups,omitempty"`
	APIKeyValidations []APIKeySection              `json:"api_key_validations,omitempty"`
	TrafficEvidence   []TrafficEntry               `json:"traffic_evidence,omitempty"`
	AppendixNotes     string                       `json:"appendix_notes,omitempty"`
}
