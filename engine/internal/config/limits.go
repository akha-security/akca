package config

import "time"

// EffectiveMaxPages returns the explicit crawl page cap. Zero means unlimited.
func (c ScanConfig) EffectiveMaxPages() int {
	return c.MaxPages
}

// EffectiveCrawlerBudget returns the max requests the crawler may make during discovery.
// It ensures the crawler leaves room for parameter discovery, reflection, and vuln scanning.
func (c ScanConfig) EffectiveCrawlerBudget() int {
	if c.CrawlerRequestBudget > 0 {
		return c.CrawlerRequestBudget
	}
	if c.RequestBudget <= 0 {
		return 0
	}
	budget := int(float64(c.RequestBudget) * 0.35)
	if budget < 1000 {
		budget = 1000
	}
	return budget
}

// MaxEndpointsLimit returns the explicit endpoint cap. Zero means unlimited.
func (c ScanConfig) MaxEndpointsLimit() int {
	return c.MaxEndpoints
}

// ModuleTargetLimit is deliberately unlimited. Discovery is capped separately,
// but every URL+method+parameter surface found within that cap must reach the
// vulnerability modules.
func (c ScanConfig) ModuleTargetLimit() int {
	return 0
}

// ParameterDiscoveryEndpointLimit follows the page cap so every crawled
// endpoint participates in hidden-parameter discovery. Zero means unlimited.
func (c ScanConfig) ParameterDiscoveryEndpointLimit() int {
	return c.EffectiveMaxPages()
}

// ParameterMaxProbes returns differential probes per endpoint during parameter
// discovery. Hidden-parameter probing is multiplicative (endpoints x names), so
// leaving this unlimited can turn an otherwise small scan into hours of traffic.
func (c ScanConfig) ParameterMaxProbes() int {
	switch c.ScanIntensity {
	case "stealth":
		return 60
	case "normal", "":
		return 320
	default: // fast
		return 96
	}
}

// ParameterWordlistCap limits active probe names per endpoint (top-priority subset).
func (c ScanConfig) ParameterWordlistCap() int {
	switch c.ScanIntensity {
	case "stealth":
		return 40
	case "normal", "":
		return 160
	default: // fast
		return 64
	}
}

// ParameterTransferMaxProbes caps the global cross-endpoint parameter transfer
// pass that runs before per-endpoint discovery.
func (c ScanConfig) ParameterTransferMaxProbes() int {
	switch c.ScanIntensity {
	case "stealth":
		return 100
	case "normal", "":
		return 1000
	default: // fast
		return 256
	}
}

// ParameterDiscoveryWorkers returns concurrent endpoint workers for param discovery.
func (c ScanConfig) ParameterDiscoveryWorkers() int {
	workers := 8
	switch c.ScanIntensity {
	case "fast":
		workers = 12
	case "stealth":
		workers = 2
	}
	if c.MaxConcurrency > 0 && workers > c.MaxConcurrency {
		workers = c.MaxConcurrency
	}
	if workers < 1 {
		workers = 1
	}
	return workers
}

// ReflectionProfileLimit caps baseline profiles loaded for module targeting.
func (c ScanConfig) ReflectionProfileLimit() int {
	return c.ModuleTargetLimit()
}

// FullModuleCoverage is true when all vulnerability modules are enabled.
func (c ScanConfig) FullModuleCoverage() bool {
	return len(c.AllowedVulnerabilityClasses) == 0
}

// OASTDrainDuration is how long to poll for blind OAST callbacks after vuln modules finish.
func (c ScanConfig) OASTDrainDuration() time.Duration {
	if !c.EnableOAST {
		return 0
	}
	if c.OASTDrainTimeout > 0 {
		return c.OASTDrainTimeout
	}
	switch c.ScanIntensity {
	case "fast":
		return 15 * time.Second
	case "stealth":
		return 90 * time.Second
	default:
		return 45 * time.Second
	}
}
