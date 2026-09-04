package report

import (
	"encoding/json"
	"fmt"
	"strings"
)

const ReportSchemaVersion = "1.0"

// ValidateJSONSchema enforces the stable, machine-consumable contract of AKCA
// JSON reports. It intentionally validates required public fields rather than
// Go implementation details so additive fields remain backwards compatible.
func ValidateJSONSchema(raw []byte) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return fmt.Errorf("invalid report JSON: %w", err)
	}
	for _, field := range []string{
		"schema_version", "generated_at", "template", "format", "partial",
		"title", "summary", "scope", "metrics", "findings",
	} {
		if _, ok := root[field]; !ok {
			return fmt.Errorf("report schema %s missing required field %q", ReportSchemaVersion, field)
		}
	}
	var version, format string
	if json.Unmarshal(root["schema_version"], &version) != nil || version != ReportSchemaVersion {
		return fmt.Errorf("unsupported report schema version %q", version)
	}
	if json.Unmarshal(root["format"], &format) != nil || format != string(FormatJSON) {
		return fmt.Errorf("report format must be %q", FormatJSON)
	}
	for _, field := range []string{"scope", "metrics"} {
		var object map[string]json.RawMessage
		if json.Unmarshal(root[field], &object) != nil || len(object) == 0 {
			return fmt.Errorf("report field %q must be a non-empty object", field)
		}
	}
	var findings []map[string]json.RawMessage
	if err := json.Unmarshal(root["findings"], &findings); err != nil {
		return fmt.Errorf("report findings must be an array: %w", err)
	}
	requiredFinding := []string{
		"id", "title", "summary", "description", "severity", "confidence",
		"confidence_score", "vuln_class", "endpoint_url", "http_evidence",
	}
	for i, finding := range findings {
		for _, field := range requiredFinding {
			if _, ok := finding[field]; !ok {
				return fmt.Errorf("finding %d missing required field %q", i, field)
			}
		}
		var class string
		if json.Unmarshal(finding["vuln_class"], &class) != nil || strings.TrimSpace(class) == "" {
			return fmt.Errorf("finding %d has no vulnerability class", i)
		}
		var confidence string
		if json.Unmarshal(finding["confidence"], &confidence) != nil {
			return fmt.Errorf("finding %d has invalid confidence", i)
		}
		var evidence struct {
			ProofSatisfied *bool `json:"proof_satisfied"`
		}
		if json.Unmarshal(finding["http_evidence"], &evidence) != nil || evidence.ProofSatisfied == nil {
			return fmt.Errorf("finding %d has no explicit proof decision", i)
		}
		if !*evidence.ProofSatisfied {
			return fmt.Errorf("finding %d is not proof-satisfied", i)
		}
		if !strings.EqualFold(confidence, "Confirmed") &&
			!strings.EqualFold(confidence, "HighConfidence") {
			return fmt.Errorf("finding %d has non-reportable confidence %q", i, confidence)
		}
	}
	return nil
}
