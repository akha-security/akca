package config

import "time"

const (
	defaultMaxEndpointsCeiling = 50_000
	unlimitedMaxPagesCeiling   = 10_000
)

// EffectiveMaxPages returns a safe crawl page cap (MaxPages 0 is not unlimited).
func (c ScanConfig) EffectiveMaxPages() int {
	if c.MaxPages > 0 {
		if c.MaxPages > unlimitedMaxPagesCeiling {
			return unlimitedMaxPagesCeiling
		}
		return c.MaxPages
	}
	switch c.ScanIntensity {
	case "fast":
		return 2000
	case "stealth":
		return 300
	default:
		return 1000
	}
}

// MaxEndpointsLimit caps persisted/discovered endpoints per scan.
func (c ScanConfig) MaxEndpointsLimit() int {
	if c.MaxEndpoints > 0 {
		return c.MaxEndpoints
	}
	return defaultMaxEndpointsCeiling
}

// ModuleTargetLimit returns how many parameter targets vuln modules may load.
func (c ScanConfig) ModuleTargetLimit() int {
	pages := c.EffectiveMaxPages()
	if pages > 2000 {
		return 2000
	}
	if pages > 0 {
		return pages
	}
	switch c.ScanIntensity {
	case "fast":
		return 1000
	case "stealth":
		return 100
	default:
		return 500
	}
}

// ParameterDiscoveryEndpointLimit caps endpoints scanned for hidden parameters.
func (c ScanConfig) ParameterDiscoveryEndpointLimit() int {
	pages := c.EffectiveMaxPages()
	limit := 100
	if pages > 0 {
		limit = pages / 2
		if limit < 80 {
			limit = 80
		}
		if limit > 600 {
			limit = 600
		}
	} else {
		switch c.ScanIntensity {
		case "fast":
			limit = 200
		case "stealth":
			limit = 40
		default:
			limit = 100
		}
	}
	return limit
}

// ParameterMaxProbes returns differential probes per endpoint during param discovery.
func (c ScanConfig) ParameterMaxProbes() int {
	switch c.ScanIntensity {
	case "fast":
		return 60
	case "stealth":
		return 30
	default:
		return 80
	}
}

// ParameterWordlistCap limits active probe names per endpoint (top-priority subset).
func (c ScanConfig) ParameterWordlistCap() int {
	switch c.ScanIntensity {
	case "fast":
		return 100
	case "stealth":
		return 50
	default:
		return 120
	}
}

// ParameterDiscoveryWorkers returns concurrent endpoint workers for param discovery.
func (c ScanConfig) ParameterDiscoveryWorkers() int {
	switch c.ScanIntensity {
	case "fast":
		return 12
	case "stealth":
		return 2
	default:
		return 8
	}
}

// ReflectionProfileLimit caps baseline profiles loaded for module targeting.
func (c ScanConfig) ReflectionProfileLimit() int {
	limit := c.ModuleTargetLimit()
	if limit > 1000 {
		return 1000
	}
	return limit
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
