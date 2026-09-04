package config

// ApplyScanIntensity fills missing rate/concurrency defaults based on scan_intensity.
// User-provided limits are never raised; a bug bounty scan must honor the
// operator's traffic budget exactly.
func ApplyScanIntensity(cfg *ScanConfig) {
	switch cfg.ScanIntensity {
	case "fast":
		if cfg.GlobalRateLimit <= 0 {
			cfg.GlobalRateLimit = 20
		}
		if cfg.PerHostRateLimit <= 0 {
			cfg.PerHostRateLimit = 10
		}
		if cfg.PerHostConcurrency <= 0 {
			cfg.PerHostConcurrency = 8
		}
		if cfg.MaxConcurrency <= 0 {
			cfg.MaxConcurrency = 16
		}
	case "stealth":
		if !cfg.Explicit.GlobalRateLimit && (cfg.GlobalRateLimit > 1 || cfg.GlobalRateLimit <= 0) {
			cfg.GlobalRateLimit = 1
		}
		if !cfg.Explicit.PerHostRateLimit && (cfg.PerHostRateLimit > 0.5 || cfg.PerHostRateLimit <= 0) {
			cfg.PerHostRateLimit = 0.5
		}
		if !cfg.Explicit.PerHostConcurrency && cfg.PerHostConcurrency > 1 {
			cfg.PerHostConcurrency = 1
		}
	case "normal", "":
		if cfg.ScanIntensity == "" {
			cfg.ScanIntensity = "normal"
		}
	}
}
