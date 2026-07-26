package policy

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/report"
	"github.com/akha-security/akca/engine/internal/storage"
)

type Config struct {
	FailOnNewSeverities     []string       `json:"fail_on_new_severities"`
	MaxConfirmedBySeverity  map[string]int `json:"max_confirmed_by_severity,omitempty"`
	MaxNewEndpoints         int            `json:"max_new_endpoints"`
	RejectUnprovenConfirmed bool           `json:"reject_unproven_confirmed"`
}

func DefaultConfig() Config {
	return Config{
		FailOnNewSeverities: []string{"critical", "high"},
		MaxNewEndpoints:     -1, RejectUnprovenConfirmed: true,
	}
}

type Finding struct {
	ID       int64  `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Class    string `json:"vuln_class"`
	Endpoint string `json:"endpoint"`
}

type Trend struct {
	CurrentConfirmed  map[string]int `json:"current_confirmed"`
	PreviousConfirmed map[string]int `json:"previous_confirmed"`
	Delta             map[string]int `json:"delta"`
	NewEndpoints      int            `json:"new_endpoints"`
	RemovedEndpoints  int            `json:"removed_endpoints"`
}

type Evaluation struct {
	CurrentScanID            string    `json:"current_scan_id"`
	PreviousScanID           string    `json:"previous_scan_id,omitempty"`
	Passed                   bool      `json:"passed"`
	Violations               []string  `json:"violations,omitempty"`
	NewConfirmed             []Finding `json:"new_confirmed,omitempty"`
	UnprovenLabeledConfirmed int       `json:"unproven_labeled_confirmed"`
	Trend                    Trend     `json:"trend"`
	EvaluatedAt              string    `json:"evaluated_at"`
	ProofGate                string    `json:"proof_gate"`
}

func Evaluate(db *storage.DB, currentScanID, previousScanID string, cfg Config) (Evaluation, error) {
	if db == nil || strings.TrimSpace(currentScanID) == "" {
		return Evaluation{}, fmt.Errorf("policy storage and current scan id are required")
	}
	currentRecords, err := db.ListFindings(currentScanID, 100000, 0)
	if err != nil {
		return Evaluation{}, err
	}
	var previousRecords []storage.FindingRecord
	if previousScanID != "" {
		previousRecords, err = db.ListFindings(previousScanID, 100000, 0)
		if err != nil {
			return Evaluation{}, err
		}
	}
	current, currentUnproven := confirmed(currentRecords)
	previous, _ := confirmed(previousRecords)
	evaluation := Evaluation{
		CurrentScanID: currentScanID, PreviousScanID: previousScanID, Passed: true,
		UnprovenLabeledConfirmed: currentUnproven,
		EvaluatedAt:              time.Now().UTC().Format(time.RFC3339),
		ProofGate:                "confidence=Confirmed AND proof_satisfied=true",
		Trend: Trend{
			CurrentConfirmed: countSeverity(current), PreviousConfirmed: countSeverity(previous),
			Delta: map[string]int{},
		},
	}
	for _, severity := range []string{"critical", "high", "medium", "low", "info"} {
		evaluation.Trend.Delta[severity] = evaluation.Trend.CurrentConfirmed[severity] -
			evaluation.Trend.PreviousConfirmed[severity]
	}
	previousSet := map[string]struct{}{}
	for _, finding := range previous {
		previousSet[findingKey(finding)] = struct{}{}
	}
	for _, finding := range current {
		if _, exists := previousSet[findingKey(finding)]; !exists {
			evaluation.NewConfirmed = append(evaluation.NewConfirmed, toFinding(finding))
		}
	}
	sort.SliceStable(evaluation.NewConfirmed, func(i, j int) bool {
		return severityRank(evaluation.NewConfirmed[i].Severity) > severityRank(evaluation.NewConfirmed[j].Severity)
	})
	blockedSeverities := stringSet(cfg.FailOnNewSeverities)
	for _, finding := range evaluation.NewConfirmed {
		if blockedSeverities[strings.ToLower(finding.Severity)] {
			evaluation.Violations = append(evaluation.Violations,
				fmt.Sprintf("new confirmed %s finding: %s", strings.ToLower(finding.Severity), finding.Title))
		}
	}
	for severity, maximum := range cfg.MaxConfirmedBySeverity {
		if maximum >= 0 && evaluation.Trend.CurrentConfirmed[strings.ToLower(severity)] > maximum {
			evaluation.Violations = append(evaluation.Violations,
				fmt.Sprintf("confirmed %s findings exceed policy maximum %d", strings.ToLower(severity), maximum))
		}
	}
	currentEndpoints, err := db.ListEndpointURLs(currentScanID)
	if err != nil {
		return Evaluation{}, err
	}
	var previousEndpoints []string
	if previousScanID != "" {
		previousEndpoints, err = db.ListEndpointURLs(previousScanID)
		if err != nil {
			return Evaluation{}, err
		}
	}
	evaluation.Trend.NewEndpoints, evaluation.Trend.RemovedEndpoints = endpointDelta(previousEndpoints, currentEndpoints)
	if cfg.MaxNewEndpoints >= 0 && evaluation.Trend.NewEndpoints > cfg.MaxNewEndpoints {
		evaluation.Violations = append(evaluation.Violations,
			fmt.Sprintf("new endpoints %d exceed policy maximum %d", evaluation.Trend.NewEndpoints, cfg.MaxNewEndpoints))
	}
	if cfg.RejectUnprovenConfirmed && currentUnproven > 0 {
		evaluation.Violations = append(evaluation.Violations,
			fmt.Sprintf("%d finding(s) labeled Confirmed do not satisfy the proof contract", currentUnproven))
	}
	evaluation.Passed = len(evaluation.Violations) == 0
	raw, err := json.Marshal(evaluation)
	if err != nil {
		return Evaluation{}, err
	}
	if err := db.SavePolicyEvaluation(currentScanID, previousScanID, evaluation.Passed, string(raw)); err != nil {
		return Evaluation{}, err
	}
	return evaluation, nil
}

func confirmed(records []storage.FindingRecord) ([]storage.FindingRecord, int) {
	out := make([]storage.FindingRecord, 0, len(records))
	unproven := 0
	for _, record := range records {
		if !strings.EqualFold(record.Confidence, "confirmed") {
			continue
		}
		if !report.FindingFromRecord(record, true).HTTPEvidence.ProofSatisfied {
			unproven++
			continue
		}
		out = append(out, record)
	}
	return out, unproven
}

func toFinding(record storage.FindingRecord) Finding {
	return Finding{
		ID: record.ID, Title: report.RedactString(record.Title), Severity: strings.ToLower(record.Severity),
		Class: record.VulnClass, Endpoint: report.RedactString(record.EndpointURL),
	}
}

func findingKey(record storage.FindingRecord) string {
	return strings.Join([]string{
		strings.ToLower(record.VulnClass), record.EndpointURL, record.Parameter, record.Title,
	}, "|")
}

func countSeverity(records []storage.FindingRecord) map[string]int {
	out := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, record := range records {
		out[strings.ToLower(record.Severity)]++
	}
	return out
}

func endpointDelta(previous, current []string) (int, int) {
	prevSet, currentSet := stringSet(previous), stringSet(current)
	var added, removed int
	for value := range currentSet {
		if !prevSet[value] {
			added++
		}
	}
	for value := range prevSet {
		if !currentSet[value] {
			removed++
		}
	}
	return added, removed
}

func stringSet(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[strings.ToLower(strings.TrimSpace(value))] = true
	}
	return out
}

func severityRank(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}
