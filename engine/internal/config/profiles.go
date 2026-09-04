package config

const (
	// A zero global request budget means vulnerability modules may run every
	// payload against every discovered target. Discovery itself stays bounded.
	FullScanRequestBudget        = 0
	FullScanCrawlerRequestBudget = 1_000
	FullScanMaxPages             = 1_000
	FullScanMaxEndpoints         = 1_000
)

// ApplyScanProfile normalizes every scan to AKCA's single exhaustive Full Scan
// mode. Legacy profile names are accepted through stored configs, but no longer
// reduce coverage or silently switch modules off.
func ApplyScanProfile(cfg ScanConfig) ScanConfig {
	if len(cfg.AllowedVulnerabilityClasses) == 0 {
		cfg.SmartScanProfile = "Full Scan"
	}
	if !cfg.Explicit.RequestBudget {
		cfg.RequestBudget = FullScanRequestBudget
	}
	if !cfg.Explicit.CrawlerRequestBudget {
		cfg.CrawlerRequestBudget = FullScanCrawlerRequestBudget
	}
	if !cfg.Explicit.MaxPages {
		cfg.MaxPages = FullScanMaxPages
	}
	if !cfg.Explicit.MaxEndpoints {
		cfg.MaxEndpoints = cfg.MaxPages
	}
	if !cfg.Explicit.MaxDepth {
		cfg.MaxDepth = 0
	}
	if !cfg.Explicit.TimeBudget {
		cfg.TimeBudget = 0
	}
	if !cfg.Explicit.EnableFuzzing {
		cfg.EnableFuzzing = true
	}
	if !cfg.Explicit.EnableOAST {
		cfg.EnableOAST = true
	}
	if !cfg.Explicit.EnableJSAnalysis {
		cfg.EnableJSAnalysis = true
	}
	if !cfg.Explicit.EnableWAFDetection {
		cfg.EnableWAFDetection = true
	}
	if !cfg.Explicit.Enable403BypassChecks {
		cfg.Enable403BypassChecks = true
	}
	if !cfg.Explicit.EnableBusinessLogicChecks {
		cfg.EnableBusinessLogicChecks = true
	}
	if !cfg.Explicit.EnableRaceConditionTesting {
		cfg.EnableRaceConditionTesting = true
	}
	if !cfg.Explicit.EnableSecondOrderTracking {
		cfg.EnableSecondOrderTracking = true
	}
	if !cfg.Explicit.EnableWAFBypassHeaders {
		cfg.EnableWAFBypassHeaders = false
	}
	if cfg.PayloadBudget == "" {
		cfg.PayloadBudget = PayloadBudgetUnlimited
	}
	if cfg.PerHostConcurrency <= 0 {
		cfg.PerHostConcurrency = 16
	}
	// Passive mode is enforced last. CLI/UI defaults are commonly applied after
	// mode selection; without this final clamp they could silently reactivate
	// mutation-capable phases while the scan was still labelled "passive".
	if cfg.PassiveMode {
		cfg.EnableFuzzing = false
		cfg.EnableOAST = false
		cfg.EnableWAFDetection = false
		cfg.Enable403BypassChecks = false
		cfg.EnableBusinessLogicChecks = false
		cfg.EnableRaceConditionTesting = false
		cfg.EnableSecondOrderTracking = false
		cfg.EnableHeadlessCrawler = false
		cfg.EnableWAFBypassHeaders = false
	}
	return cfg
}
