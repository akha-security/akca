package integrations

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/report"
)

func fixtureFindings() []report.FindingEntry {
	return []report.FindingEntry{
		{
			ID: 1, Title: "SQL injection", Severity: "high", Confidence: "Confirmed",
			VulnClass: "sqli", EndpointURL: "https://example.test/items?id=1", Parameter: "id",
			Description: "Authorization: Bearer secret-token-123",
			Remediation: "Use parameterized queries",
			HTTPEvidence: report.HTTPEvidence{
				ProofSatisfied: true, Payload: `' OR 1=1--`, Location: "query",
			},
		},
		{
			ID: 2, Title: "Heuristic only", Severity: "high", Confidence: "Potential",
			VulnClass: "sqli", HTTPEvidence: report.HTTPEvidence{ProofSatisfied: false},
		},
		{
			ID: 3, Title: "Confirmed label without proof", Severity: "medium", Confidence: "Confirmed",
			VulnClass: "xss", HTTPEvidence: report.HTTPEvidence{ProofSatisfied: false},
		},
	}
}

func TestAllIntegrationsShareProofGateAndPreserveRawEvidence(t *testing.T) {
	for _, kind := range []Kind{Jira, GitHubIssues, Slack, Teams, DefectDojo, WAF} {
		raw, err := Export(kind, fixtureFindings())
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		var envelope Envelope
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatalf("%s invalid JSON: %v", kind, err)
		}
		if envelope.ConfirmedCount != 1 || envelope.FilteredCount != 2 {
			t.Fatalf("%s proof gate failed: %+v", kind, envelope)
		}
		if strings.Contains(string(raw), "[REDACTED]") || strings.Contains(string(raw), "Heuristic only") {
			t.Fatalf("%s redaction/proof gate mismatch: %s", kind, raw)
		}
	}
}

func TestWAFExportIsMonitorOnlyAndEscaped(t *testing.T) {
	findings := fixtureFindings()
	findings[0].HTTPEvidence.Payload = "\"\nmalicious"
	raw, err := Export(WAF, findings)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `"mode": "monitor_only"`) ||
		!strings.Contains(text, "review before deny mode") ||
		strings.Contains(text, ",deny,") {
		t.Fatalf("unsafe WAF export: %s", text)
	}
}
