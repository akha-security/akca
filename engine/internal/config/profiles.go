package config

// ApplyScanProfile merges smart scan profile defaults into cfg without overwriting
// explicit user-provided limits from Settings.
func ApplyScanProfile(cfg ScanConfig) ScanConfig {
	switch cfg.SmartScanProfile {
	case "QuickRecon":
		setIfZero(&cfg.MaxDepth, 2)
		setIfZero(&cfg.MaxPages, 150)
		if !cfg.Explicit.EnableFuzzing {
			cfg.EnableFuzzing = false
		}
		if !cfg.Explicit.EnableOAST {
			cfg.EnableOAST = false
		}
		if cfg.PayloadBudget == "" {
			cfg.PayloadBudget = PayloadBudgetLow
		}
		setIfZero(&cfg.PerHostConcurrency, 2)
	case "FullBugBounty":
		setIfZero(&cfg.MaxDepth, 4)
		setIfZero(&cfg.MaxPages, 500)
		if !cfg.Explicit.EnableFuzzing {
			cfg.EnableFuzzing = true
		}
		if !cfg.Explicit.EnableOAST {
			cfg.EnableOAST = true
		}
		if !cfg.Explicit.EnableJSAnalysis {
			cfg.EnableJSAnalysis = true
		}
		cfg.EnableWAFDetection = true
		cfg.Enable403BypassChecks = true
		if cfg.PayloadBudget == "" {
			cfg.PayloadBudget = PayloadBudgetMedium
		}
		setIfZero(&cfg.PerHostConcurrency, 16)
	case "APIDeepScan":
		setIfZero(&cfg.MaxDepth, 3)
		setIfZero(&cfg.MaxPages, 800)
		if !cfg.Explicit.EnableFuzzing {
			cfg.EnableFuzzing = true
		}
		if cfg.PayloadBudget == "" {
			cfg.PayloadBudget = PayloadBudgetHigh
		}
		setIfZero(&cfg.PerHostConcurrency, 4)
	case "AuthenticatedAppScan":
		setIfZero(&cfg.MaxDepth, 5)
		setIfZero(&cfg.MaxPages, 600)
		if !cfg.Explicit.EnableFuzzing {
			cfg.EnableFuzzing = true
		}
		setIfZero(&cfg.PerHostConcurrency, 3)
	case "LowNoiseWAFFriendly":
		if !cfg.Explicit.GlobalRateLimit && (cfg.GlobalRateLimit <= 0 || cfg.GlobalRateLimit > 1) {
			cfg.GlobalRateLimit = 1
		}
		if !cfg.Explicit.PerHostRateLimit && (cfg.PerHostRateLimit <= 0 || cfg.PerHostRateLimit > 0.5) {
			cfg.PerHostRateLimit = 0.5
		}
		if !cfg.Explicit.PerHostConcurrency {
			setIfZero(&cfg.PerHostConcurrency, 1)
		}
		if cfg.PayloadBudget == "" {
			cfg.PayloadBudget = PayloadBudgetLow
		}
		if !cfg.Explicit.EnableFuzzing {
			cfg.EnableFuzzing = false
		}
	case "JavaScriptHeavySPA":
		setIfZero(&cfg.MaxDepth, 5)
		setIfZero(&cfg.MaxPages, 900)
		if !cfg.Explicit.PerHostConcurrency {
			setIfZero(&cfg.PerHostConcurrency, 4)
		}
		if !cfg.Explicit.EnableFuzzing {
			cfg.EnableFuzzing = true
		}
		cfg.EnableHeadlessCrawler = true
		if !cfg.Explicit.EnableJSAnalysis {
			cfg.EnableJSAnalysis = true
		}
	case "OASTBlindTesting":
		if !cfg.Explicit.EnableOAST {
			cfg.EnableOAST = true
		}
		if !cfg.Explicit.EnableFuzzing {
			cfg.EnableFuzzing = true
		}
		if cfg.PayloadBudget == "" {
			cfg.PayloadBudget = PayloadBudgetMedium
		}
	}
	return cfg
}

func setIfZero(field *int, value int) {
	if *field <= 0 {
		*field = value
	}
}
