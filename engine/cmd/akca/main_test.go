package main

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindingStatusDoesNotCallManualReviewVerified(t *testing.T) {
	glyph, label, _, confirmed := findingStatus("NeedsManualReview")
	if confirmed || label != "MANUAL REVIEW" || glyph != "◇" {
		t.Fatalf("manual review status was mislabelled: glyph=%q label=%q confirmed=%v", glyph, label, confirmed)
	}

	glyph, label, _, confirmed = findingStatus("Confirmed")
	if !confirmed || label != "CONFIRMED" || glyph != "◆" {
		t.Fatalf("confirmed status was not represented as proven: glyph=%q label=%q confirmed=%v", glyph, label, confirmed)
	}

	glyph, label, _, confirmed = findingStatus("HighConfidence")
	if confirmed || label != "HIGH CONFIDENCE" || glyph != "◇" {
		t.Fatalf("high-confidence status was not represented live: glyph=%q label=%q confirmed=%v", glyph, label, confirmed)
	}
}

func TestFlagWasSetDistinguishesDefaultBoolFromExplicitChoice(t *testing.T) {
	fs := flag.NewFlagSet("akca", flag.ContinueOnError)
	var wafEvasion bool
	fs.BoolVar(&wafEvasion, "waf-evasion", false, "")
	if flagWasSet(fs, "waf-evasion") {
		t.Fatal("unset bool flag should not be reported as set")
	}
	if err := fs.Parse([]string{"--waf-evasion=false"}); err != nil {
		t.Fatal(err)
	}
	if !flagWasSet(fs, "waf-evasion") || wafEvasion {
		t.Fatalf("explicit false should be tracked without enabling: set=%v value=%v", flagWasSet(fs, "waf-evasion"), wafEvasion)
	}
}

func TestFindingProofExplainsTimingState(t *testing.T) {
	if got := findingProof("timing_differential", map[string]interface{}{"timing_confirmed": true}); got != "Paired timing controls passed" {
		t.Fatalf("confirmed timing proof = %q", got)
	}
	if got := findingProof("timing_differential", nil); got != "Timing signal requires manual reproduction" {
		t.Fatalf("manual timing proof = %q", got)
	}
}

func TestSessionOASTStatus(t *testing.T) {
	status, _ := sessionOASTStatus(map[string]interface{}{"oast_enabled": true})
	if status != "READY" {
		t.Fatalf("enabled OAST status = %q", status)
	}
	status, _ = sessionOASTStatus(map[string]interface{}{"oast_enabled": false})
	if status != "OFF" {
		t.Fatalf("disabled OAST status = %q", status)
	}
}

func TestScanSessionPanelIsCompactAndUsesStringTargets(t *testing.T) {
	panel := scanSessionPanel(map[string]interface{}{
		"targets":           []string{"http://burpbountylab.com"},
		"global_rate_limit": 50.0,
		"max_pages":         1000,
		"scan_profile":      "FullBugBounty",
		"oast_enabled":      true,
	})
	for _, want := range []string{
		"http://burpbountylab.com", "FullBugBounty", "50 req/s",
		"1000 pages", "OAST READY", "RUNNING",
	} {
		if !strings.Contains(panel, want) {
			t.Fatalf("session panel omitted %q: %q", want, panel)
		}
	}
	if strings.Contains(panel, "[OAST ACTIVE]") || strings.Contains(panel, "domain=") {
		t.Fatalf("legacy duplicate OAST banner leaked into session panel: %q", panel)
	}
	lines := strings.Split(strings.TrimSuffix(panel, "\n\n"), "\n")
	if len(lines) != 6 {
		t.Fatalf("session panel should remain compact, lines=%d: %q", len(lines), panel)
	}
	for _, line := range lines {
		if visibleLen(line) > uiWidth+4 {
			t.Fatalf("session panel line overflows (%d columns): %q", visibleLen(line), line)
		}
	}
}

func TestTrafficAdjustmentUsesTitleCaseAndDeduplicates(t *testing.T) {
	text := trafficAdjustmentText(map[string]interface{}{
		"global_rate_limit":    3,
		"per_host_rate_limit":  1,
		"max_concurrency":      4,
		"per_host_concurrency": 1,
	})
	if text != "Rate 3/s  Host 1/s  Workers 4/1" {
		t.Fatalf("unexpected traffic text: %q", text)
	}
	cw := NewConsoleWriter()
	if !cw.acceptTrafficUpdate(text) || cw.acceptTrafficUpdate(text) {
		t.Fatal("identical traffic update must be printed exactly once")
	}
}

func TestBenchmarkCommandWritesObservedJSON(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "benchmark.json")
	code := runBenchmarkCommand([]string{
		"--db", filepath.Join(dir, "benchmark.db"),
		"--output", output,
		"--strict",
	})
	if code != 0 {
		t.Fatalf("benchmark command exited with %d", code)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Results []struct {
			Scenario  string `json:"scenario"`
			Synthetic bool   `json:"synthetic_fixture"`
			Requests  int    `json:"requests"`
		} `json:"results"`
		QualityGate struct {
			Passed    bool            `json:"passed"`
			Synthetic bool            `json:"synthetic"`
			Checks    map[string]bool `json:"checks"`
		} `json:"quality_gate"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Results) == 0 || payload.QualityGate.Synthetic || !payload.QualityGate.Passed {
		t.Fatalf("benchmark output is not observed: %+v", payload)
	}
	for _, check := range []string{"request_budget", "duration_budget", "determinism", "goroutine_leak", "report_schema"} {
		if !payload.QualityGate.Checks[check] {
			t.Fatalf("benchmark operational check failed or is missing: %s", check)
		}
	}
	var aggregateRequests int
	for _, result := range payload.Results {
		if result.Synthetic {
			t.Fatalf("synthetic result leaked into observed benchmark: %+v", result)
		}
		if result.Scenario == "aggregate" {
			aggregateRequests = result.Requests
		}
	}
	if aggregateRequests == 0 {
		t.Fatal("observed aggregate request count is missing")
	}
}
