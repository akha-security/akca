package benchmark

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/testlab"
)

type Scenario struct {
	ID            string `json:"id"`
	VulnClass     string `json:"vuln_class"`
	Fixture       string `json:"fixture"`
	EndpointPath  string `json:"endpoint_path,omitempty"`
	TargetMode    string `json:"target_mode"`
	Vulnerable    bool   `json:"vulnerable"`
	Capability    string `json:"capability,omitempty"`
	MatchEvidence string `json:"match_evidence,omitempty"`
}

type Result struct {
	Scenario                string   `json:"scenario"`
	VulnClass               string   `json:"vuln_class,omitempty"`
	Fixture                 string   `json:"fixture,omitempty"`
	DetectionRate           float64  `json:"detection_rate"`
	FalsePositiveRate       float64  `json:"false_positive_rate"`
	Requests                int      `json:"requests"`
	ReplayRequests          int      `json:"replay_requests,omitempty"`
	RequestRepeatDriftRatio float64  `json:"request_repeat_drift_ratio,omitempty"`
	DurationSec             float64  `json:"duration_sec"`
	Confidence              float64  `json:"confidence"`
	Detected                bool     `json:"detected"`
	Precision               float64  `json:"precision,omitempty"`
	Recall                  float64  `json:"recall,omitempty"`
	Specificity             float64  `json:"specificity,omitempty"`
	F1                      float64  `json:"f1,omitempty"`
	FPRUpper95              float64  `json:"false_positive_rate_upper_95,omitempty"`
	TruePositive            int      `json:"true_positive,omitempty"`
	FalsePositive           int      `json:"false_positive,omitempty"`
	TrueNegative            int      `json:"true_negative,omitempty"`
	FalseNegative           int      `json:"false_negative,omitempty"`
	Synthetic               bool     `json:"synthetic_fixture"`
	Confirmed               bool     `json:"confirmed,omitempty"`
	Skipped                 bool     `json:"skipped,omitempty"`
	SkipReason              string   `json:"skip_reason,omitempty"`
	BaselineRequests        int      `json:"baseline_requests,omitempty"`
	RequestRegressionRatio  float64  `json:"request_regression_ratio,omitempty"`
	BaselineDurationSec     float64  `json:"baseline_duration_sec,omitempty"`
	DurationRegressionRatio float64  `json:"duration_regression_ratio,omitempty"`
	Deterministic           bool     `json:"deterministic,omitempty"`
	DeterminismMismatches   []string `json:"determinism_mismatches,omitempty"`
	GoroutineDelta          int      `json:"goroutine_delta,omitempty"`
	ReportSchemaCompatible  bool     `json:"report_schema_compatible,omitempty"`
}

type Lab struct {
	db *storage.DB
}

type observedRun struct {
	result   testlab.Result
	duration time.Duration
}

func NewLab(db *storage.DB) *Lab {
	return &Lab{db: db}
}

func DefaultScenarios() []Scenario {
	scenarios := []Scenario{
		{ID: "sqli_error_boolean_vulnerable", VulnClass: "sqli", Fixture: "real SQL branch fixture", EndpointPath: "/api/users", TargetMode: "full", Vulnerable: true},
		{ID: "ssrf_metadata_vulnerable", VulnClass: "ssrf", Fixture: "provider metadata fixture", EndpointPath: "/api/fetch", TargetMode: "full", Vulnerable: true},
		{ID: "ssrf_oast_callback_vulnerable", VulnClass: "ssrf", Fixture: "correlated local HTTP callback fixture", EndpointPath: "/api/fetch", TargetMode: "full", Vulnerable: true, Capability: "oast", MatchEvidence: "oast_callback"},
		{ID: "xxe_entity_vulnerable", VulnClass: "xxe", Fixture: "XML entity expansion fixture", EndpointPath: "/xml", TargetMode: "full", Vulnerable: true},
		{ID: "lfi_traversal_vulnerable", VulnClass: "lfi", Fixture: "two traversal encoding fixture", EndpointPath: "/download", TargetMode: "full", Vulnerable: true},
		{ID: "open_redirect_vulnerable", VulnClass: "open_redirect", Fixture: "external Location fixture", EndpointPath: "/redirect", TargetMode: "full", Vulnerable: true},
		{ID: "javascript_secret_vulnerable", VulnClass: "secret_exposure", Fixture: "live JavaScript secret fixture", EndpointPath: "/static/app.js", TargetMode: "full", Vulnerable: true},
		{ID: "xss_browser_execution_vulnerable", VulnClass: "xss", Fixture: "headless-browser DOM execution fixture", EndpointPath: "/search", TargetMode: "full", Vulnerable: true, Capability: "browser", MatchEvidence: "dom_execution"},
		{ID: "broken_auth_anonymous_access_vulnerable", VulnClass: "broken_auth", Fixture: "authenticated resource anonymous replay fixture", EndpointPath: "/auth/profile", TargetMode: "full", Vulnerable: true, Capability: "auth"},
		{ID: "jwt_alg_none_identity_vulnerable", VulnClass: "jwt", Fixture: "captured valid, invalid, expired, and alg:none identity fixture", EndpointPath: "/parity/auth/jwt", TargetMode: "full", Vulnerable: true, Capability: "auth_parity"},
		{ID: "oauth_redirect_uri_vulnerable", VulnClass: "oauth", Fixture: "state-bound authorization-code redirect fixture", EndpointPath: "/parity/oauth/authorize", TargetMode: "full", Vulnerable: true, Capability: "auth_parity"},
		{ID: "account_enumeration_vulnerable", VulnClass: "account_enum", Fixture: "interleaved known/unknown stable response fixture", EndpointPath: "/parity/auth/forgot", TargetMode: "full", Vulnerable: true, Capability: "auth_parity"},
		{ID: "rate_limit_missing_vulnerable", VulnClass: "rate_limit", Fixture: "configured account threshold fixture", EndpointPath: "/parity/auth/login", TargetMode: "full", Vulnerable: true, Capability: "auth_parity"},
		{ID: "mass_assignment_state_vulnerable", VulnClass: "mass_assignment", Fixture: "persisted role mutation with cleanup fixture", EndpointPath: "/parity/api/profile", TargetMode: "full", Vulnerable: true, Capability: "auth_parity"},

		{ID: "constant_framework_error_safe", VulnClass: "sqli", Fixture: "constant SQL-looking framework error", EndpointPath: "/api/users", TargetMode: "patched"},
		{ID: "ssrf_payload_echo_safe", VulnClass: "ssrf", Fixture: "escaped URL payload echo", EndpointPath: "/api/fetch", TargetMode: "patched"},
		{ID: "xxe_normal_parser_safe", VulnClass: "xxe", Fixture: "non-expanding XML parser", EndpointPath: "/xml", TargetMode: "patched"},
		{ID: "lfi_path_echo_safe", VulnClass: "lfi", Fixture: "file-name echo without retrieval", EndpointPath: "/download", TargetMode: "patched"},
		{ID: "redirect_same_origin_safe", VulnClass: "open_redirect", Fixture: "forced same-origin redirect", EndpointPath: "/redirect", TargetMode: "patched"},
		{ID: "javascript_bundle_safe", VulnClass: "secret_exposure", Fixture: "credential-free JavaScript bundle", EndpointPath: "/static/app.js", TargetMode: "patched"},
		{ID: "encoded_reflection_safe", VulnClass: "xss", Fixture: "HTML-encoded reflection", EndpointPath: "/search", TargetMode: "patched"},
		{ID: "waf_block_page_safe", VulnClass: "xss", Fixture: "WAF block response", EndpointPath: "/waf-probe", TargetMode: "full"},
		{ID: "graphql_introspection_only_safe", VulnClass: "graphql", Fixture: "introspection metadata only", EndpointPath: "/graphql", TargetMode: "full"},
		{ID: "graphql_typename_safe", VulnClass: "graphql", Fixture: "typename response without abuse", EndpointPath: "/graphql", TargetMode: "patched"},
		{ID: "public_profile_safe", VulnClass: "sensitive_data", Fixture: "public profile without PII", EndpointPath: "/profile", TargetMode: "patched"},
		{ID: "actuator_not_found_safe", VulnClass: "debug_admin", Fixture: "404 actuator control", EndpointPath: "/actuator/health", TargetMode: "patched"},
		{ID: "admin_forbidden_safe", VulnClass: "access_control_bypass", Fixture: "header bypass rejected", EndpointPath: "/admin", TargetMode: "patched"},
		{ID: "idempotent_race_safe", VulnClass: "race_condition", Fixture: "single-side-effect race lead", EndpointPath: "/coupon/claim", TargetMode: "full"},
		{ID: "broken_auth_rejected_safe", VulnClass: "broken_auth", Fixture: "anonymous request rejected fixture", EndpointPath: "/auth/profile", TargetMode: "patched", Capability: "auth"},
		{ID: "jwt_alg_none_rejected_safe", VulnClass: "jwt", Fixture: "alg:none rejected with valid and expired controls", EndpointPath: "/parity/auth/jwt", TargetMode: "patched", Capability: "auth_parity"},
		{ID: "oauth_exact_redirect_safe", VulnClass: "oauth", Fixture: "registered redirect exact-match enforcement", EndpointPath: "/parity/oauth/authorize", TargetMode: "patched", Capability: "auth_parity"},
		{ID: "account_enumeration_generic_safe", VulnClass: "account_enum", Fixture: "uniform known/unknown recovery response", EndpointPath: "/parity/auth/forgot", TargetMode: "patched", Capability: "auth_parity"},
		{ID: "rate_limit_enforced_safe", VulnClass: "rate_limit", Fixture: "configured threshold block response", EndpointPath: "/parity/auth/login", TargetMode: "patched", Capability: "auth_parity"},
		{ID: "mass_assignment_ignored_safe", VulnClass: "mass_assignment", Fixture: "server-side privilege-field allowlist", EndpointPath: "/parity/api/profile", TargetMode: "patched", Capability: "auth_parity"},
	}
	classes := []struct {
		class, path, fixture string
	}{
		{"xss", "search", "context-encoded reflection control"},
		{"sqli", "api/users", "independent validation and generic-error control"},
		{"ssrf", "api/fetch", "allowlist, echo, and gateway control"},
		{"lfi", "download", "filename echo and not-found control"},
	}
	for i := 0; i < testlab.ParityNegativeVariants; i++ {
		for _, class := range classes {
			scenarios = append(scenarios, Scenario{
				ID:        fmt.Sprintf("parity_%s_safe_%02d", class.class, i),
				VulnClass: class.class, Fixture: class.fixture,
				EndpointPath: fmt.Sprintf("/parity/safe/%s/%02d", class.path, i),
				TargetMode:   "patched",
			})
		}
	}
	return scenarios
}

func (l *Lab) RunAll() ([]Result, error) {
	return l.RunObserved(context.Background())
}

func (l *Lab) RunObserved(ctx context.Context) ([]Result, error) {
	if l == nil || l.db == nil {
		return nil, errors.New("benchmark storage is required")
	}
	goroutinesBefore := runtime.NumGoroutine()
	baseline, baselineAvailable := l.latestAggregate()
	runID := time.Now().UTC().UnixNano()
	fullLab := testlab.NewServer(testlab.ModeFull)
	defer fullLab.Close()
	patchedLab := testlab.NewServer(testlab.ModeV2)
	defer patchedLab.Close()

	fullStart := time.Now()
	full, err := testlab.RunScan(ctx, l.db, testlab.Options{
		ScanID: fmt.Sprintf("benchmark-full-%d", runID), Lab: fullLab, Short: true,
		EnableBrowser: true, EnableOAST: true, EnableAuth: true, EnableAuthParity: true,
	})
	if err != nil {
		return nil, fmt.Errorf("run vulnerable benchmark target: %w", err)
	}
	fullDuration := time.Since(fullStart)
	patchedStart := time.Now()
	patched, err := testlab.RunScan(ctx, l.db, testlab.Options{
		ScanID: fmt.Sprintf("benchmark-patched-%d", runID), Lab: patchedLab, Short: true,
		EnableBrowser: true, EnableOAST: true, EnableAuth: true, EnableAuthParity: true,
		ParityCorpusSize: testlab.ParityNegativeVariants,
	})
	if err != nil {
		return nil, fmt.Errorf("run patched benchmark target: %w", err)
	}
	patchedDuration := time.Since(patchedStart)

	replayFullLab := testlab.NewServer(testlab.ModeFull)
	defer replayFullLab.Close()
	replayPatchedLab := testlab.NewServer(testlab.ModeV2)
	defer replayPatchedLab.Close()
	replayFull, err := testlab.RunScan(ctx, l.db, testlab.Options{
		ScanID: fmt.Sprintf("benchmark-determinism-full-%d", runID), Lab: replayFullLab, Short: true,
		EnableBrowser: true, EnableOAST: true, EnableAuth: true, EnableAuthParity: true,
	})
	if err != nil {
		return nil, fmt.Errorf("run deterministic vulnerable benchmark target: %w", err)
	}
	replayPatched, err := testlab.RunScan(ctx, l.db, testlab.Options{
		ScanID: fmt.Sprintf("benchmark-determinism-patched-%d", runID), Lab: replayPatchedLab, Short: true,
		EnableBrowser: true, EnableOAST: true, EnableAuth: true, EnableAuthParity: true,
		ParityCorpusSize: testlab.ParityNegativeVariants,
	})
	if err != nil {
		return nil, fmt.Errorf("run deterministic patched benchmark target: %w", err)
	}

	runs := map[string]observedRun{
		"full":    {result: full, duration: fullDuration},
		"patched": {result: patched, duration: patchedDuration},
	}
	replayRuns := map[string]testlab.Result{"full": replayFull, "patched": replayPatched}
	scenarios := DefaultScenarios()
	determinismMismatches := compareObservedRuns(runs, replayRuns, scenarios)
	results := make([]Result, 0, len(scenarios)+16)
	tp, fp, tn, fn := 0, 0, 0, 0
	moduleCounts := make(map[string][4]int)
	for _, sc := range scenarios {
		run, ok := runs[sc.TargetMode]
		if !ok {
			return nil, fmt.Errorf("unknown benchmark target mode %q", sc.TargetMode)
		}
		if sc.Capability != "" && !run.result.Capabilities[sc.Capability] {
			r := Result{
				Scenario: sc.ID, VulnClass: sc.VulnClass, Fixture: sc.Fixture,
				Requests: int(run.result.RequestCount), DurationSec: run.duration.Seconds(),
				Synthetic: false, Skipped: true, SkipReason: "capability unavailable: " + sc.Capability,
			}
			results = append(results, r)
			raw, _ := json.Marshal(r)
			if err := l.db.SaveBenchmarkResult(sc.ID, string(raw)); err != nil {
				return nil, err
			}
			continue
		}
		detected, confidence, confirmed := observedFinding(run.result.Findings, sc)
		r := Result{
			Scenario: sc.ID, VulnClass: sc.VulnClass, Fixture: sc.Fixture,
			DetectionRate:     boolRate(detected && sc.Vulnerable),
			FalsePositiveRate: boolRate(detected && !sc.Vulnerable),
			Requests:          int(run.result.RequestCount), DurationSec: run.duration.Seconds(),
			Confidence: confidence, Detected: detected, Confirmed: confirmed, Synthetic: false,
		}
		results = append(results, r)
		counts := moduleCounts[sc.VulnClass]
		if sc.Vulnerable && detected {
			tp++
			counts[0]++
		} else if sc.Vulnerable && !detected {
			fn++
			counts[3]++
		} else if !sc.Vulnerable && detected {
			fp++
			counts[1]++
		} else {
			tn++
			counts[2]++
		}
		moduleCounts[sc.VulnClass] = counts
		raw, _ := json.Marshal(r)
		if err := l.db.SaveBenchmarkResult(sc.ID, string(raw)); err != nil {
			return nil, err
		}
	}
	for module, counts := range moduleCounts {
		m := metricsFromCounts(counts[0], counts[1], counts[2], counts[3])
		result := Result{
			Scenario: "module:" + module, VulnClass: module,
			DetectionRate: m.Recall, FalsePositiveRate: m.FalsePositiveRate,
			Precision: m.Precision, Recall: m.Recall, Specificity: m.Specificity,
			F1: m.F1, FPRUpper95: m.FPRUpper95,
			TruePositive: counts[0], FalsePositive: counts[1],
			TrueNegative: counts[2], FalseNegative: counts[3],
			Synthetic: false,
		}
		results = append(results, result)
		raw, _ := json.Marshal(result)
		if err := l.db.SaveBenchmarkResult(result.Scenario, string(raw)); err != nil {
			return nil, err
		}
	}
	metrics := metricsFromCounts(tp, fp, tn, fn)
	fullLab.Close()
	patchedLab.Close()
	replayFullLab.Close()
	replayPatchedLab.Close()
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	goroutineDelta := runtime.NumGoroutine() - goroutinesBefore
	if goroutineDelta < 0 {
		goroutineDelta = 0
	}
	requests := int(full.RequestCount + patched.RequestCount)
	replayRequests := int(replayFull.RequestCount + replayPatched.RequestCount)
	durationSec := (fullDuration + patchedDuration).Seconds()
	summary := Result{
		Scenario:                "aggregate",
		DetectionRate:           metrics.Recall,
		FalsePositiveRate:       metrics.FalsePositiveRate,
		Requests:                requests,
		ReplayRequests:          replayRequests,
		RequestRepeatDriftRatio: absoluteRegressionRatio(float64(replayRequests), float64(requests)),
		DurationSec:             durationSec,
		Confidence:              metrics.Precision,
		Precision:               metrics.Precision,
		Recall:                  metrics.Recall,
		Specificity:             metrics.Specificity,
		F1:                      metrics.F1,
		FPRUpper95:              metrics.FPRUpper95,
		TruePositive:            tp,
		FalsePositive:           fp,
		TrueNegative:            tn,
		FalseNegative:           fn,
		Synthetic:               false,
		Deterministic:           len(determinismMismatches) == 0,
		DeterminismMismatches:   determinismMismatches,
		GoroutineDelta:          goroutineDelta,
		ReportSchemaCompatible: full.ReportSchemaCompatible && patched.ReportSchemaCompatible &&
			replayFull.ReportSchemaCompatible && replayPatched.ReportSchemaCompatible,
	}
	if baselineAvailable {
		summary.BaselineRequests = baseline.Requests
		summary.BaselineDurationSec = baseline.DurationSec
		summary.RequestRegressionRatio = regressionRatio(float64(requests), float64(baseline.Requests))
		summary.DurationRegressionRatio = regressionRatio(durationSec, baseline.DurationSec)
	}
	raw, _ := json.Marshal(summary)
	if err := l.db.SaveBenchmarkResult("aggregate", string(raw)); err != nil {
		return nil, err
	}
	results = append(results, summary)
	return results, nil
}

func (l *Lab) latestAggregate() (Result, bool) {
	rows, err := l.db.ListBenchmarkResults(1000)
	if err != nil {
		return Result{}, false
	}
	for _, row := range rows {
		if row.Scenario != "aggregate" {
			continue
		}
		var result Result
		if json.Unmarshal([]byte(row.ResultJSON), &result) == nil && result.Requests > 0 && result.DurationSec > 0 {
			return result, true
		}
	}
	return Result{}, false
}

func compareObservedRuns(primary map[string]observedRun, replay map[string]testlab.Result, scenarios []Scenario) []string {
	var mismatches []string
	for _, scenario := range scenarios {
		first, ok := primary[scenario.TargetMode]
		second, okReplay := replay[scenario.TargetMode]
		if !ok || !okReplay {
			mismatches = append(mismatches, scenario.ID+": target missing")
			continue
		}
		firstAvailable := scenario.Capability == "" || first.result.Capabilities[scenario.Capability]
		secondAvailable := scenario.Capability == "" || second.Capabilities[scenario.Capability]
		if firstAvailable != secondAvailable {
			mismatches = append(mismatches, scenario.ID+": capability changed")
			continue
		}
		if !firstAvailable {
			continue
		}
		firstDetected, _, firstConfirmed := observedFinding(first.result.Findings, scenario)
		secondDetected, _, secondConfirmed := observedFinding(second.Findings, scenario)
		if firstDetected != secondDetected || firstConfirmed != secondConfirmed {
			mismatches = append(mismatches, scenario.ID+": finding decision changed")
		}
	}
	return mismatches
}

func regressionRatio(current, baseline float64) float64 {
	if baseline <= 0 {
		return 0
	}
	return (current - baseline) / baseline
}

func absoluteRegressionRatio(current, baseline float64) float64 {
	return math.Abs(regressionRatio(current, baseline))
}

type GateConfig struct {
	MinimumPrecision                 float64 `json:"minimum_precision"`
	MinimumRecall                    float64 `json:"minimum_recall"`
	MinimumModulePrecision           float64 `json:"minimum_module_precision"`
	MinimumModuleRecall              float64 `json:"minimum_module_recall"`
	MaximumConfirmedFP               int     `json:"maximum_confirmed_false_positives"`
	MaximumFPRUpper95                float64 `json:"maximum_fpr_upper_95"`
	MaximumRequests                  int     `json:"maximum_requests"`
	MaximumRequestRepeatDriftRatio   float64 `json:"maximum_request_repeat_drift_ratio"`
	MaximumDurationSec               float64 `json:"maximum_duration_sec"`
	MaximumRequestRegressionRatio    float64 `json:"maximum_request_regression_ratio"`
	MaximumDurationRegressionRatio   float64 `json:"maximum_duration_regression_ratio"`
	MaximumGoroutineDelta            int     `json:"maximum_goroutine_delta"`
	RequireDeterminism               bool    `json:"require_determinism"`
	RequireReportSchemaCompatibility bool    `json:"require_report_schema_compatibility"`
	AllowSynthetic                   bool    `json:"allow_synthetic"`
}

func StrictGateConfig() GateConfig {
	return GateConfig{
		MinimumPrecision: 0.995, MinimumRecall: 0.80, MaximumConfirmedFP: 0,
		MinimumModulePrecision: 0.995, MinimumModuleRecall: 0.80,
		MaximumFPRUpper95: 0.05, MaximumRequests: 2300, MaximumRequestRepeatDriftRatio: 0.02, MaximumDurationSec: 45,
		MaximumRequestRegressionRatio: 0.20, MaximumDurationRegressionRatio: 0.75,
		MaximumGoroutineDelta: 8, RequireDeterminism: true,
		RequireReportSchemaCompatibility: true, AllowSynthetic: false,
	}
}

type GateReport struct {
	Passed     bool            `json:"passed"`
	Metrics    Metrics         `json:"metrics"`
	Violations []string        `json:"violations,omitempty"`
	Synthetic  bool            `json:"synthetic"`
	Checks     map[string]bool `json:"checks,omitempty"`
}

func EvaluateQualityGate(scenarios []Scenario, results []Result, cfg GateConfig) GateReport {
	expected := make(map[string]bool, len(scenarios))
	for _, scenario := range scenarios {
		expected[scenario.ID] = scenario.Vulnerable
	}
	tp, fp, tn, fn := 0, 0, 0, 0
	synthetic := false
	var aggregate *Result
	var moduleResults []Result
	for _, result := range results {
		if result.Scenario == "aggregate" {
			copy := result
			aggregate = &copy
			continue
		}
		if strings.HasPrefix(result.Scenario, "module:") {
			moduleResults = append(moduleResults, result)
			continue
		}
		vulnerable, ok := expected[result.Scenario]
		if !ok || result.Skipped {
			continue
		}
		synthetic = synthetic || result.Synthetic
		switch {
		case vulnerable && result.Detected:
			tp++
		case vulnerable:
			fn++
		case result.Detected:
			fp++
		default:
			tn++
		}
	}
	metrics := metricsFromCounts(tp, fp, tn, fn)
	report := GateReport{Passed: true, Metrics: metrics, Synthetic: synthetic, Checks: map[string]bool{}}
	if metrics.Precision < cfg.MinimumPrecision {
		report.Violations = append(report.Violations, "precision below required threshold")
	}
	if metrics.Recall < cfg.MinimumRecall {
		report.Violations = append(report.Violations, "recall below required threshold")
	}
	if fp > cfg.MaximumConfirmedFP {
		report.Violations = append(report.Violations, "confirmed false-positive budget exceeded")
	}
	if metrics.FPRUpper95 > cfg.MaximumFPRUpper95 {
		report.Violations = append(report.Violations, "false-positive upper confidence bound exceeded")
	}
	if synthetic && !cfg.AllowSynthetic {
		report.Violations = append(report.Violations, "synthetic corpus cannot satisfy the release gate")
	}
	for _, module := range moduleResults {
		if module.TruePositive+module.FalsePositive > 0 && module.Precision < cfg.MinimumModulePrecision {
			report.Violations = append(report.Violations, module.Scenario+" precision below required threshold")
		}
		if module.TruePositive+module.FalseNegative > 0 && module.Recall < cfg.MinimumModuleRecall {
			report.Violations = append(report.Violations, module.Scenario+" recall below required threshold")
		}
	}
	if aggregate != nil {
		report.Checks["request_budget"] = cfg.MaximumRequests <= 0 || aggregate.Requests <= cfg.MaximumRequests
		report.Checks["request_repeat_stability"] = cfg.MaximumRequestRepeatDriftRatio <= 0 ||
			aggregate.RequestRepeatDriftRatio <= cfg.MaximumRequestRepeatDriftRatio
		report.Checks["duration_budget"] = cfg.MaximumDurationSec <= 0 || aggregate.DurationSec <= cfg.MaximumDurationSec
		report.Checks["request_regression"] = aggregate.BaselineRequests <= 0 ||
			aggregate.RequestRegressionRatio <= cfg.MaximumRequestRegressionRatio
		report.Checks["duration_regression"] = aggregate.BaselineDurationSec <= 0 ||
			aggregate.DurationRegressionRatio <= cfg.MaximumDurationRegressionRatio
		report.Checks["determinism"] = !cfg.RequireDeterminism || aggregate.Deterministic
		report.Checks["goroutine_leak"] = cfg.MaximumGoroutineDelta < 0 ||
			aggregate.GoroutineDelta <= cfg.MaximumGoroutineDelta
		report.Checks["report_schema"] = !cfg.RequireReportSchemaCompatibility || aggregate.ReportSchemaCompatible
		for _, check := range []string{
			"request_budget", "request_repeat_stability", "duration_budget", "request_regression", "duration_regression",
			"determinism", "goroutine_leak", "report_schema",
		} {
			if !report.Checks[check] {
				report.Violations = append(report.Violations, check+" quality gate failed")
			}
		}
	}
	report.Passed = len(report.Violations) == 0
	return report
}

func observedFinding(findings []storage.FindingRecord, scenario Scenario) (bool, float64, bool) {
	bestScore := 0.0
	confirmed := false
	for _, finding := range findings {
		if !strings.EqualFold(strings.TrimSpace(finding.VulnClass), strings.TrimSpace(scenario.VulnClass)) {
			continue
		}
		if scenario.EndpointPath != "" && findingPath(finding.EndpointURL) != strings.ToLower(scenario.EndpointPath) {
			continue
		}
		if scenario.MatchEvidence != "" && !strings.Contains(strings.ToLower(finding.EvidenceJSON+" "+finding.Description), strings.ToLower(scenario.MatchEvidence)) {
			continue
		}
		if finding.ConfidenceScore > bestScore {
			bestScore = finding.ConfidenceScore
		}
		if strings.EqualFold(finding.Confidence, "Confirmed") {
			confirmed = true
		}
	}
	return bestScore > 0 || confirmed, bestScore, confirmed
}

func findingPath(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Path)
}

func ScenarioResults(results []Result) []Result {
	out := make([]Result, 0, len(results))
	for _, result := range results {
		if result.Scenario == "aggregate" || strings.HasPrefix(result.Scenario, "module:") {
			continue
		}
		out = append(out, result)
	}
	return out
}

type Metrics struct {
	Precision         float64
	Recall            float64
	Specificity       float64
	F1                float64
	FalsePositiveRate float64
	FPRUpper95        float64
}

func metricsFromCounts(tp, fp, tn, fn int) Metrics {
	precision := rate(tp, tp+fp)
	recall := rate(tp, tp+fn)
	specificity := rate(tn, tn+fp)
	f1 := 0.0
	if precision+recall > 0 {
		f1 = 2 * precision * recall / (precision + recall)
	}
	return Metrics{
		Precision: precision, Recall: recall, Specificity: specificity, F1: f1,
		FalsePositiveRate: rate(fp, fp+tn), FPRUpper95: wilsonUpper(fp, fp+tn),
	}
}

func wilsonUpper(successes, total int) float64 {
	if total <= 0 {
		return 0
	}
	z := 1.96
	n := float64(total)
	p := float64(successes) / n
	denom := 1 + z*z/n
	center := p + z*z/(2*n)
	margin := z * math.Sqrt((p*(1-p)+z*z/(4*n))/n)
	return math.Min(1, (center+margin)/denom)
}

func rate(num, den int) float64 {
	if den == 0 {
		return 0
	}
	return float64(num) / float64(den)
}

func boolRate(v bool) float64 {
	if v {
		return 1
	}
	return 0
}
