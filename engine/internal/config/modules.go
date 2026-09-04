package config

import "strings"

// AllowsModule reports whether a vulnerability module may run under this scan config.
func (c ScanConfig) AllowsModule(module string) bool {
	switch module {
	case "business_logic":
		if !c.EnableBusinessLogicChecks {
			return false
		}
	case "race_condition", "race_condition_sync":
		if !c.EnableRaceConditionTesting {
			return false
		}
	case "second_order":
		if !c.EnableSecondOrderTracking {
			return false
		}
	case "security_headers", "tls_misconfig", "cookie_security", "api_versioning", "http_methods":
		if !c.EnableInformationalChecks && len(c.AllowedVulnerabilityClasses) == 0 {
			return false
		}
	}
	if len(c.AllowedVulnerabilityClasses) == 0 {
		return true
	}
	mod := strings.ToLower(strings.TrimSpace(module))
	for _, allowed := range c.AllowedVulnerabilityClasses {
		a := strings.ToLower(strings.TrimSpace(allowed))
		if a == mod || a == moduleAlias(mod) {
			return true
		}
	}
	return false
}

func moduleAlias(module string) string {
	switch module {
	case "command_injection":
		return "cmdinj"
	case "cache_poisoning":
		return "cache_poison"
	case "vulnerable_components", "known_cve":
		return "cve"
	case "crlf":
		return "response_splitting"
	default:
		return module
	}
}
