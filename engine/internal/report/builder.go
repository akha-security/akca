package report

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/evidencestore"
	"github.com/akha-security/akca/engine/internal/findingtext"
	"github.com/akha-security/akca/engine/internal/storage"
)

type Builder struct {
	store *evidencestore.Store
	db    *storage.DB
}

func NewBuilder(store *evidencestore.Store, db *storage.DB) *Builder {
	return &Builder{store: store, db: db}
}

func (b *Builder) BuildMeta(opts Options) (Document, error) {
	doc := Document{
		SchemaVersion: ReportSchemaVersion,
		GeneratedAt:   time.Now().UTC(),
		Template:      opts.Template,
		Format:        opts.Format,
		Partial:       opts.Partial,
		Title:         templateTitle(opts.Template),
		Summary:       templateSummary(opts.Template),
		Scope:         b.buildScope(opts.ScanID),
	}
	metrics, err := b.db.DashboardMetrics(opts.ScanID)
	if err != nil {
		return doc, err
	}
	doc.Metrics = b.reportMetrics(opts, metrics)
	groups, err := b.db.ListFindingGroups(opts.ScanID, 100)
	if err != nil {
		return doc, err
	}
	doc.RootCauseGroups = groups
	doc.APIKeyValidations = b.buildAPIKeySection(opts.ScanID, opts.Redact)
	doc.TrafficEvidence = b.buildTrafficSection(opts.ScanID, opts.Redact)
	if opts.Template == TemplateInternal || opts.Template == TemplateAppendix {
		doc.ManualLeads = b.buildManualLeads(opts)
	}
	if opts.Template == TemplateAppendix {
		doc.AppendixNotes = "Technical evidence appendix — raw request/response excerpts are redacted by default."
	}
	return doc, nil
}

func (b *Builder) buildManualLeads(opts Options) []ManualLeadEntry {
	confidences := opts.Confidences
	if len(confidences) == 0 {
		confidences = []string{"Confirmed", "HighConfidence", "Potential", "NeedsManualReview"}
	}
	filter := storage.FindingsFilter{
		ScanID: opts.ScanID, Confidences: confidences,
		Severities: opts.Severities, VulnClasses: opts.VulnClasses,
		FindingIDs: opts.FindingIDs, SearchQuery: opts.SearchQuery,
	}
	var out []ManualLeadEntry
	_ = b.db.IterateFindingsFiltered(filter, func(rec storage.FindingRecord) error {
		entry := FindingFromRecord(rec, opts.Redact)
		if reportableFinding(entry, opts.Template) {
			return nil
		}
		out = append(out, ManualLeadEntry{
			Finding: entry,
			Warning: "This lead was not automatically proven and must not be submitted as a bug-bounty finding.",
		})
		return nil
	})
	return out
}

func (b *Builder) buildTrafficSection(scanID string, redact bool) []TrafficEntry {
	records, err := b.db.ListRequestResponses(scanID, 100)
	if err != nil {
		return nil
	}
	out := make([]TrafficEntry, 0, len(records))
	for _, rec := range records {
		rawRequest, rawResponse := storage.RawHTTPFromRecord(rec)
		if redact {
			rawRequest = RedactString(rawRequest)
			rawResponse = RedactString(rawResponse)
		}
		out = append(out, TrafficEntry{Method: rec.Method, URL: rec.URL, StatusCode: rec.StatusCode, DurationMs: rec.DurationMs, RawRequest: rawRequest, RawResponse: rawResponse})
	}
	return out
}

func (b *Builder) buildScope(scanID string) ScopeSection {
	sec := ScopeSection{ScanID: scanID}
	cfg, _ := b.db.GetScanConfig(scanID)
	var parsed struct {
		Targets []string `json:"targets"`
	}
	_ = json.Unmarshal([]byte(cfg), &parsed)
	sec.Targets = parsed.Targets
	return sec
}

func (b *Builder) buildAPIKeySection(scanID string, redact bool) []APIKeySection {
	recs, _ := b.db.ListAPIKeyValidationRecords(scanID, 200)
	out := make([]APIKeySection, 0, len(recs))
	for _, rec := range recs {
		details := rec.ResultJSON
		if redact {
			details = RedactString(details)
		}
		out = append(out, APIKeySection{
			Service:     rec.Service,
			Status:      rec.Status,
			Risk:        APIKeyRisk(rec.Status, rec.Service),
			Remediation: APIKeyRemediation(rec.Status, rec.Service),
			Details:     details,
		})
	}
	return out
}

func FindingFromRecord(rec storage.FindingRecord, redact bool) FindingEntry {
	desc := stripEmbeddedEvidence(rec.Description)
	if desc == "" {
		desc = rec.Summary
	}
	httpEv := httpEvidenceFromRecord(rec)
	entry := FindingEntry{
		ID:                rec.ID,
		Title:             findingtext.DisplayTitle(rec.VulnClass, rec.Title),
		Summary:           rec.Summary,
		Description:       desc,
		Severity:          rec.Severity,
		Confidence:        rec.Confidence,
		ConfidenceScore:   rec.ConfidenceScore,
		ConfidenceExplain: confidenceExplanation(rec.Confidence),
		VulnClass:         rec.VulnClass,
		EndpointURL:       rec.EndpointURL,
		Parameter:         rec.Parameter,
		ReproductionSteps: defaultReproduction(rec),
		Impact:            defaultImpact(rec),
		Remediation:       defaultRemediation(rec),
		HTTPEvidence:      httpEv,
		ReplayCommand:     fmt.Sprintf("akca replay --finding %d", rec.ID),
	}
	if httpEv.ProofType != "" {
		entry.EvidenceSummary = fmt.Sprintf("%s proof under policy %s (%d observations)",
			httpEv.ProofType, httpEv.ProofPolicy, len(httpEv.Observations))
	}
	if !httpEv.ProofSatisfied {
		entry.ConfidenceExplain = "Stored confidence label is not backed by a satisfied proof policy; this record is quarantined for manual review."
	}
	if rec.Parameter == "" && httpEv.Parameter != "" {
		entry.Parameter = httpEv.Parameter
	}
	if rec.EndpointURL != "" {
		entry.AffectedInstances = []string{rec.EndpointURL}
	}
	if redact {
		RedactFinding(&entry)
	}
	return entry
}

// ReportFinding is the single submission gate used by every output format.
// Confidence labels are presentation metadata, not proof: a finding can only
// enter the primary report when its stored evidence satisfies the proof policy.
func (b *Builder) ReportFinding(rec storage.FindingRecord, opts Options) (FindingEntry, bool) {
	entry := FindingFromRecord(rec, opts.Redact)
	return entry, reportableFinding(entry, opts.Template)
}

func reportableFinding(entry FindingEntry, template TemplateKind) bool {
	if !entry.HTTPEvidence.ProofSatisfied {
		return false
	}
	if template == TemplateHackerOne || template == TemplateBugcrowd {
		return strings.EqualFold(entry.Confidence, "Confirmed")
	}
	return strings.EqualFold(entry.Confidence, "Confirmed") ||
		strings.EqualFold(entry.Confidence, "HighConfidence")
}

func (b *Builder) CountReportableFindings(opts Options) int {
	count := 0
	_ = b.db.IterateFindingsFiltered(b.Filter(opts), func(rec storage.FindingRecord) error {
		if _, ok := b.ReportFinding(rec, opts); ok {
			count++
		}
		return nil
	})
	return count
}

func (b *Builder) reportMetrics(opts Options, base storage.DashboardMetrics) storage.DashboardMetrics {
	base.TotalFindings = 0
	base.BySeverity = map[string]int{}
	base.ByConfidence = map[string]int{}
	base.ByVulnClass = map[string]int{}
	_ = b.db.IterateFindingsFiltered(b.Filter(opts), func(rec storage.FindingRecord) error {
		entry, ok := b.ReportFinding(rec, opts)
		if !ok {
			return nil
		}
		base.TotalFindings++
		base.BySeverity[entry.Severity]++
		base.ByConfidence[entry.Confidence]++
		base.ByVulnClass[entry.VulnClass]++
		return nil
	})
	return base
}

func (b *Builder) Filter(opts Options) storage.FindingsFilter {
	confidences := opts.Confidences
	if len(confidences) == 0 {
		// Bug-bounty output is proof-only by default. Developer/internal
		// reports may also include the strong but not exploit-confirmed tier.
		if opts.Template == TemplateHackerOne || opts.Template == TemplateBugcrowd {
			confidences = []string{"Confirmed"}
		} else {
			confidences = []string{"Confirmed", "HighConfidence"}
		}
	}
	return storage.FindingsFilter{
		ScanID:      opts.ScanID,
		Severities:  opts.Severities,
		Confidences: confidences,
		VulnClasses: opts.VulnClasses,
		FindingIDs:  opts.FindingIDs,
		SearchQuery: opts.SearchQuery,
	}
}

func templateTitle(t TemplateKind) string {
	switch t {
	case TemplateHackerOne:
		return "HackerOne Submission Report"
	case TemplateBugcrowd:
		return "Bugcrowd Submission Report"
	case TemplateInternal:
		return "Akca Security Scanner - Internal Penetration Test Report"
	case TemplateExecutive:
		return "Executive Summary"
	case TemplateAppendix:
		return "Technical Evidence Appendix"
	default:
		return "Akca Security Report"
	}
}

func templateSummary(t TemplateKind) string {
	switch t {
	case TemplateExecutive:
		return "High-level overview of identified security issues, business impact, and prioritized remediation."
	case TemplateAppendix:
		return "Detailed technical evidence supporting findings from the automated scan."
	default:
		return "Bug-bounty-ready report with scope, reproduction steps, evidence, impact, and remediation guidance."
	}
}

func confidenceExplanation(label string) string {
	switch label {
	case "Confirmed":
		return "Verified with deterministic evidence (e.g., callback, error-based proof, or replay confirmation)."
	case "HighConfidence":
		return "Strong indicators with multiple corroborating signals; manual validation recommended."
	case "Potential":
		return "Heuristic or behavioral match; requires manual confirmation before submission."
	default:
		return "Insufficient automated verification; treat as lead until manually validated."
	}
}

func defaultReproduction(rec storage.FindingRecord) []string {
	steps := []string{
		"Open a browser or HTTP client scoped to the authorized target.",
	}
	if rec.EndpointURL != "" {
		steps = append(steps, fmt.Sprintf("Navigate to %s", rec.EndpointURL))
	}
	if rec.Parameter != "" {
		steps = append(steps, fmt.Sprintf("Modify parameter %q with the payload described in evidence.", rec.Parameter))
	} else {
		steps = append(steps, "Replay the request shown in the evidence section.")
	}
	steps = append(steps, "Observe the response for the vulnerability indicator described in the finding.")
	return steps
}

func defaultImpact(rec storage.FindingRecord) string {
	switch strings.ToLower(rec.Severity) {
	case "critical":
		return "Critical impact — may lead to full compromise, data exfiltration, or unauthorized administrative access."
	case "high":
		return "High impact — significant confidentiality, integrity, or availability risk to the application or users."
	case "medium":
		return "Medium impact — limited exploitation scope but meaningful security weakness."
	case "low":
		return "Low impact — defense-in-depth issue or limited exploitability."
	default:
		return "Impact depends on deployment context; review evidence and business logic."
	}
}

func defaultRemediation(rec storage.FindingRecord) string {
	switch strings.ToLower(rec.VulnClass) {
	case "xss", "cross_site_scripting":
		return "Encode output contextually, enforce CSP, and validate/sanitize user input."
	case "sqli", "sql_injection":
		return "Use parameterized queries/ORM bindings; deny list-based input concatenation."
	case "ssrf":
		return "Restrict outbound requests, block metadata IPs, and validate URL schemes/hosts."
	case "idor", "bfla":
		return "Enforce object-level authorization on every sensitive action."
	default:
		return "Apply vendor security guidance and fix the root cause identified in evidence."
	}
}
