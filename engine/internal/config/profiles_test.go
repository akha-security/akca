package config

import "testing"

func TestApplyScanProfileQuickRecon(t *testing.T) {
	cfg := ScanConfig{SmartScanProfile: "QuickRecon"}
	cfg = ApplyScanProfile(cfg)
	if cfg.EnableFuzzing {
		t.Fatal("QuickRecon should disable fuzzing")
	}
	if cfg.MaxDepth != 2 {
		t.Fatalf("expected depth 2, got %d", cfg.MaxDepth)
	}
	if cfg.MaxPages != 150 {
		t.Fatalf("expected max pages 150, got %d", cfg.MaxPages)
	}
}

func TestApplyScanProfileLowNoise(t *testing.T) {
	cfg := DefaultScanConfig()
	cfg.SmartScanProfile = "LowNoiseWAFFriendly"
	cfg = ApplyScanProfile(cfg)
	if cfg.GlobalRateLimit != 1 {
		t.Fatalf("expected rate 1, got %v", cfg.GlobalRateLimit)
	}
}

func TestApplyScanProfileHonorsExplicitDisables(t *testing.T) {
	cfg := DefaultScanConfig()
	cfg.SmartScanProfile = "FullBugBounty"
	cfg.EnableOAST = false
	cfg.EnableFuzzing = false
	cfg.EnableJSAnalysis = false
	cfg.EnableWAFBypassHeaders = false
	cfg.Explicit.EnableOAST = true
	cfg.Explicit.EnableFuzzing = true
	cfg.Explicit.EnableJSAnalysis = true
	cfg.Explicit.EnableWAFBypassHeaders = true

	cfg = ApplyScanProfile(cfg)
	if cfg.EnableOAST || cfg.EnableFuzzing || cfg.EnableJSAnalysis || cfg.EnableWAFBypassHeaders {
		t.Fatalf("profile re-enabled explicit disables: oast=%v fuzzing=%v js=%v waf=%v",
			cfg.EnableOAST, cfg.EnableFuzzing, cfg.EnableJSAnalysis, cfg.EnableWAFBypassHeaders)
	}
}

func TestFullBugBountyEnablesWAFEvasionByDefault(t *testing.T) {
	cfg := DefaultScanConfig()
	if !cfg.EnableWAFBypassHeaders {
		t.Fatal("default FullBugBounty config should enable WAF evasion")
	}
	cfg.EnableWAFBypassHeaders = false
	cfg.SmartScanProfile = "FullBugBounty"
	cfg = ApplyScanProfile(cfg)
	if !cfg.EnableWAFBypassHeaders {
		t.Fatal("FullBugBounty profile should enable WAF evasion unless explicitly disabled")
	}
}

func TestApplyScanIntensityDoesNotRaiseUserLimits(t *testing.T) {
	cfg := DefaultScanConfig()
	cfg.ScanIntensity = "fast"
	cfg.GlobalRateLimit = 5
	cfg.PerHostRateLimit = 2
	cfg.MaxConcurrency = 2
	cfg.PerHostConcurrency = 1

	ApplyScanIntensity(&cfg)
	if cfg.GlobalRateLimit != 5 || cfg.PerHostRateLimit != 2 ||
		cfg.MaxConcurrency != 2 || cfg.PerHostConcurrency != 1 {
		t.Fatalf("fast intensity raised user limits: %+v", cfg)
	}
}
