package benchmark

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/storage"
)

func TestLabRunAll(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/akca.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	results, err := NewLab(db).RunAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(results) < 20 {
		t.Fatalf("expected many scenario results, got %d", len(results))
	}
	var aggregate bool
	var oastObserved, authObserved, browserAccounted bool
	for _, result := range results {
		if result.Synthetic {
			t.Fatalf("observed benchmark result was marked synthetic: %+v", result)
		}
		if result.Scenario == "aggregate" {
			aggregate = true
			if result.Requests == 0 {
				t.Fatal("aggregate benchmark did not record real request usage")
			}
			if result.FalsePositive != 0 {
				t.Fatalf("observed benchmark promoted false positives: %+v", result)
			}
			if result.Recall < 0.80 || result.Precision < 0.995 {
				t.Fatalf("observed benchmark missed the parity thresholds: %+v", result)
			}
			if result.FPRUpper95 > 0.05 {
				t.Fatalf("negative corpus is too small or noisy for the strict FP bound: %+v", result)
			}
			if !result.Deterministic || len(result.DeterminismMismatches) != 0 {
				t.Fatalf("benchmark decisions were not deterministic: %+v", result)
			}
			if !result.ReportSchemaCompatible {
				t.Fatal("generated reports violated the versioned JSON schema")
			}
		}
		switch result.Scenario {
		case "ssrf_oast_callback_vulnerable":
			oastObserved = result.Detected && result.Confirmed
		case "broken_auth_anonymous_access_vulnerable":
			authObserved = result.Detected && result.Confirmed
		case "xss_browser_execution_vulnerable":
			browserAccounted = result.Detected || (result.Skipped && result.SkipReason != "")
		}
	}
	if !aggregate {
		t.Fatal("aggregate benchmark result is missing")
	}
	if !oastObserved || !authObserved || !browserAccounted {
		t.Fatalf("capability scenarios were not accounted for: oast=%v auth=%v browser=%v", oastObserved, authObserved, browserAccounted)
	}
	gate := EvaluateQualityGate(DefaultScenarios(), results, StrictGateConfig())
	if !gate.Passed {
		t.Fatalf("strict operational quality gate failed: %+v", gate)
	}
	rows, err := db.ListBenchmarkResults(5)
	if err != nil || len(rows) == 0 {
		t.Fatalf("benchmark rows missing: %v", err)
	}
}

func TestOperationalGateRejectsRegressions(t *testing.T) {
	scenarios := []Scenario{{ID: "positive", VulnClass: "xss", Vulnerable: true}}
	results := []Result{
		{Scenario: "positive", VulnClass: "xss", Detected: true},
		{Scenario: "module:xss", VulnClass: "xss", Precision: 1, Recall: 1, TruePositive: 1},
		{
			Scenario: "aggregate", Requests: 3000, DurationSec: 90,
			BaselineRequests: 1000, RequestRegressionRatio: 2,
			BaselineDurationSec: 30, DurationRegressionRatio: 2,
			Deterministic: false, GoroutineDelta: 20, ReportSchemaCompatible: false,
		},
	}
	report := EvaluateQualityGate(scenarios, results, StrictGateConfig())
	if report.Passed || len(report.Violations) < 5 {
		t.Fatalf("operational regressions were not rejected: %+v", report)
	}
	for _, check := range []string{"request_budget", "duration_budget", "determinism", "goroutine_leak", "report_schema"} {
		if report.Checks[check] {
			t.Fatalf("failed operational check reported as passing: %s", check)
		}
	}
}

func TestDefaultScenariosCoverage(t *testing.T) {
	sc := DefaultScenarios()
	if len(sc) < 80 {
		t.Fatalf("expected broad scenario coverage, got %d", len(sc))
	}
	for _, scenario := range sc {
		if scenario.TargetMode == "" || scenario.EndpointPath == "" || scenario.Fixture == "" {
			t.Fatalf("scenario is not backed by an observed fixture: %+v", scenario)
		}
	}
}

func TestStrictGateIgnoresUnavailableCapability(t *testing.T) {
	scenarios := []Scenario{
		{ID: "positive", Vulnerable: true},
		{ID: "browser", Vulnerable: true, Capability: "browser"},
	}
	results := []Result{
		{Scenario: "positive", Detected: true},
		{Scenario: "browser", Skipped: true, SkipReason: "capability unavailable: browser"},
	}
	cfg := StrictGateConfig()
	cfg.MaximumFPRUpper95 = 1
	report := EvaluateQualityGate(scenarios, results, cfg)
	if !report.Passed || report.Metrics.Recall != 1 {
		t.Fatalf("unavailable optional capability distorted the release gate: %+v", report)
	}
}

func TestMetricsExposeFalsePositiveUncertainty(t *testing.T) {
	m := metricsFromCounts(90, 2, 98, 10)
	if m.FalsePositiveRate != 0.02 {
		t.Fatalf("unexpected false-positive rate: %f", m.FalsePositiveRate)
	}
	if m.Precision < 0.97 || m.Recall != 0.90 || m.F1 == 0 {
		t.Fatalf("unexpected classification metrics: %+v", m)
	}
	if m.FPRUpper95 <= m.FalsePositiveRate {
		t.Fatalf("95%% upper bound must expose sample uncertainty: %+v", m)
	}
}

func TestStrictGateRejectsSyntheticAndConfirmedFalsePositive(t *testing.T) {
	scenarios := []Scenario{
		{ID: "positive", Vulnerable: true},
		{ID: "negative", Vulnerable: false},
	}
	results := []Result{
		{Scenario: "positive", Detected: true, Confirmed: true, Synthetic: true},
		{Scenario: "negative", Detected: true, Confirmed: true, Synthetic: true},
	}
	report := EvaluateQualityGate(scenarios, results, StrictGateConfig())
	if report.Passed || len(report.Violations) == 0 {
		t.Fatalf("unsafe benchmark must fail the gate: %+v", report)
	}
}
