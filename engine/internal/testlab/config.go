package testlab

import (
	"time"

	"github.com/akha-security/akca/engine/internal/config"
)

func labScanConfig(short bool) config.ScanConfig {
	cfg := config.DefaultScanConfig()
	cfg.SmartScanProfile = ""
	cfg.EnableHeadlessCrawler = false
	cfg.EnableBrowserWorkerPool = false
	cfg.EnableHealthMonitoring = false
	cfg.EnableFindingCorrelation = false
	cfg.EnableScanResume = false
	cfg.EnableScanScheduler = false
	cfg.CredentialStorageMode = config.CredentialStorageMemory
	cfg.EnableOAST = false
	cfg.FollowRedirects = false
	cfg.GlobalRateLimit = 1000
	cfg.PerHostRateLimit = 1000
	cfg.MaxConcurrency = 4
	cfg.PayloadBudget = config.PayloadBudgetLow
	cfg.EnableJSAnalysis = true
	cfg.EnableWAFDetection = true
	cfg.Enable403BypassChecks = true
	cfg.EnableRaceConditionTesting = true
	cfg.EnableBusinessLogicChecks = true

	if short {
		cfg.EnableFuzzing = false
		cfg.ScanIntensity = "fast"
		cfg.MaxPages = 12
		cfg.MaxDepth = 2
		cfg.RequestBudget = 600
		cfg.TimeBudget = 180 * time.Second
		cfg.MaxConcurrency = 2
		return cfg
	}

	cfg.EnableFuzzing = true
	cfg.MaxPages = 24
	cfg.MaxDepth = 3
	cfg.RequestBudget = 4000
	cfg.TimeBudget = 12 * time.Minute
	return cfg
}
