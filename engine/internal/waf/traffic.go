package waf

import "github.com/akha-security/akca/engine/internal/models"

// TrafficBudget is the effective upper bound used after WAF fingerprinting.
// Values are caps: an operator-provided value that is already lower is kept.
type TrafficBudget struct {
	GlobalRateLimit    float64 `json:"global_rate_limit"`
	PerHostRateLimit   float64 `json:"per_host_rate_limit"`
	MaxConcurrency     int     `json:"max_concurrency"`
	PerHostConcurrency int     `json:"per_host_concurrency"`
	Reason             string  `json:"reason"`
	Adjusted           bool    `json:"adjusted"`
}

func RecommendTrafficBudget(profile models.WAFProfile, globalRate, perHostRate float64, maxConcurrency, perHostConcurrency int) TrafficBudget {
	budget := TrafficBudget{
		GlobalRateLimit: globalRate, PerHostRateLimit: perHostRate,
		MaxConcurrency: maxConcurrency, PerHostConcurrency: perHostConcurrency,
	}
	if !profile.CautiousModeRecommended {
		return budget
	}

	globalCap, hostCap := 3.0, 1.0
	maxWorkers, hostWorkers := 4, 1
	budget.Reason = "waf_detected"
	if profile.RateLimitDetected || profile.ChallengePageDetected {
		globalCap, hostCap = 1.0, 0.5
		maxWorkers, hostWorkers = 2, 1
		budget.Reason = "active_waf_challenge_or_rate_limit"
	}

	budget.GlobalRateLimit = capPositiveFloat(globalRate, globalCap)
	budget.PerHostRateLimit = capPositiveFloat(perHostRate, hostCap)
	budget.MaxConcurrency = capPositiveInt(maxConcurrency, maxWorkers)
	budget.PerHostConcurrency = capPositiveInt(perHostConcurrency, hostWorkers)
	budget.Adjusted = budget.GlobalRateLimit != globalRate || budget.PerHostRateLimit != perHostRate ||
		budget.MaxConcurrency != maxConcurrency || budget.PerHostConcurrency != perHostConcurrency
	return budget
}

func capPositiveFloat(current, cap float64) float64 {
	if current <= 0 || current > cap {
		return cap
	}
	return current
}

func capPositiveInt(current, cap int) int {
	if current <= 0 || current > cap {
		return cap
	}
	return current
}
