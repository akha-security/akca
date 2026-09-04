package config

import "testing"

func TestDefaultUsesSingleFullScanProfile(t *testing.T) {
	cfg := ApplyScanProfile(DefaultScanConfig())
	if cfg.SmartScanProfile != "Full Scan" {
		t.Fatalf("default profile = %q, want Full Scan", cfg.SmartScanProfile)
	}
	if cfg.RequestBudget != 0 || cfg.CrawlerRequestBudget != 1_000 {
		t.Fatalf("unexpected request budgets: total=%d crawler=%d", cfg.RequestBudget, cfg.CrawlerRequestBudget)
	}
	if cfg.MaxPages != 1_000 || cfg.MaxEndpoints != 1_000 || cfg.MaxDepth != 0 {
		t.Fatalf("unexpected full scan coverage limits: pages=%d endpoints=%d depth=%d", cfg.MaxPages, cfg.MaxEndpoints, cfg.MaxDepth)
	}
	if cfg.PayloadBudget != PayloadBudgetUnlimited || cfg.TimeBudget != 0 || cfg.MaxMemoryMB != 0 {
		t.Fatalf("full scan must be exhaustive but memory-safe: %+v", cfg)
	}
}

func TestLegacyProfilesNormalizeToFullScan(t *testing.T) {
	for _, legacy := range []string{"Balanced", "QuickRecon", "FullBugBounty", "APIDeepScan", "JavaScriptHeavySPA"} {
		cfg := ApplyScanProfile(ScanConfig{SmartScanProfile: legacy})
		if cfg.SmartScanProfile != "Full Scan" || cfg.RequestBudget != 0 || cfg.CrawlerRequestBudget != 1_000 || cfg.MaxPages != 1_000 || cfg.MaxEndpoints != 1_000 {
			t.Fatalf("legacy profile %q was not normalized: %+v", legacy, cfg)
		}
	}
}

func TestFullScanHonorsExplicitTrafficLimitsAndFeatureDisables(t *testing.T) {
	cfg := DefaultScanConfig()
	cfg.RequestBudget = 200_000
	cfg.CrawlerRequestBudget = 50_000
	cfg.MaxPages = 10_000
	cfg.TimeBudget = 2
	cfg.EnableOAST = false
	cfg.EnableFuzzing = false
	cfg.EnableJSAnalysis = false
	cfg.Explicit.RequestBudget = true
	cfg.Explicit.CrawlerRequestBudget = true
	cfg.Explicit.MaxPages = true
	cfg.Explicit.TimeBudget = true
	cfg.Explicit.EnableOAST = true
	cfg.Explicit.EnableFuzzing = true
	cfg.Explicit.EnableJSAnalysis = true

	cfg = ApplyScanProfile(cfg)
	if cfg.RequestBudget != 200_000 || cfg.CrawlerRequestBudget != 50_000 || cfg.MaxPages != 10_000 || cfg.MaxEndpoints != 10_000 || cfg.TimeBudget != 2 {
		t.Fatalf("explicit limits were overwritten: %+v", cfg)
	}
	if cfg.EnableOAST || cfg.EnableFuzzing || cfg.EnableJSAnalysis {
		t.Fatalf("explicit feature disables were overwritten: %+v", cfg)
	}
}

func TestFullScanEnablesCompleteCoverage(t *testing.T) {
	cfg := ApplyScanProfile(ScanConfig{})
	if !cfg.EnableWAFDetection || !cfg.Enable403BypassChecks || !cfg.EnableBusinessLogicChecks ||
		!cfg.EnableRaceConditionTesting || !cfg.EnableSecondOrderTracking || !cfg.EnableOAST ||
		!cfg.EnableFuzzing || !cfg.EnableJSAnalysis {
		t.Fatalf("full scan coverage was not enabled: %+v", cfg)
	}
	if cfg.EnableWAFBypassHeaders {
		t.Fatal("WAF bypass headers must remain opt-in")
	}
}
