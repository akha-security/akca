package config

import (
	"fmt"
	"sort"
	"strings"
)

// ScanModeInfo represents a named scanner execution mode.
type ScanModeInfo struct {
	Name        string
	Aliases     []string
	Description string
	Modules     []string
	IsPassive   bool
}

// AvailableModes defines the curated set of scanning modes in AKCA.
var AvailableModes = []ScanModeInfo{
	{
		Name:        "full",
		Aliases:     []string{"all", "default"},
		Description: "Complete comprehensive vulnerability assessment (all active and passive modules)",
		Modules:     nil, // all modules
	},
	{
		Name:        "sql",
		Aliases:     []string{"sqli", "database", "db"},
		Description: "Deep SQL & NoSQL injection testing across all parameters and payloads",
		Modules:     []string{"sqli", "nosql"},
	},
	{
		Name:        "xss",
		Aliases:     []string{"cross-site-scripting"},
		Description: "Reflected, Stored, DOM, and Blind XSS scanning, prototype pollution, and client-side SSTI",
		Modules:     []string{"xss", "blind_xss", "client_ssti", "prototype_pollution"},
	},
	{
		Name:        "api",
		Aliases:     []string{"rest", "json", "endpoints"},
		Description: "REST/JSON API security, OpenAPI/Swagger analysis, BOLA/IDOR, Mass Assignment, and Token validation",
		Modules: []string{
			"api_exposure", "api_versioning", "mass_assignment", "idor", "bfla",
			"http_methods", "hpp", "jwt", "oauth", "broken_auth", "improper_auth",
			"rate_limit", "account_enum",
		},
	},
	{
		Name:        "graphql",
		Aliases:     []string{"gql"},
		Description: "GraphQL security assessment (Introspection, schema extraction, query batching, and complexity abuse)",
		Modules:     []string{"graphql"},
	},
	{
		Name:        "rce",
		Aliases:     []string{"cmdinj", "command_injection", "injection", "ssti", "code_exec"},
		Description: "Remote code execution, command injection, SSTI template injection, and deserialization",
		Modules: []string{
			"command_injection", "ssti", "client_ssti", "insecure_deserialization",
			"ldap", "xpath", "ldap_xpath_injection",
		},
	},
	{
		Name:        "ssrf",
		Aliases:     []string{"oast", "callback"},
		Description: "Server-Side Request Forgery (SSRF), XXE, Blind Out-Of-Band callback testing",
		Modules:     []string{"ssrf", "xxe", "blind_xss", "llm_injection"},
	},
	{
		Name:        "auth",
		Aliases:     []string{"privesc", "access_control", "authorization"},
		Description: "Authentication bypass, privilege escalation, BFLA, IDOR, session & cookie security",
		Modules: []string{
			"broken_auth", "improper_auth", "idor", "bfla", "jwt", "oauth",
			"csrf", "cookie_security", "security_headers",
		},
	},
	{
		Name:        "passive",
		Aliases:     []string{"safe", "recon", "no-attack"},
		Description: "Zero-attack non-invasive inspection: secret leaks, API keys, cookies, TLS, and metadata",
		Modules: []string{
			"security_headers", "cookie_security", "sensitive_data", "secret_exposure",
			"tls_misconfig", "vulnerable_components", "known_cve",
		},
		IsPassive: true,
	},
	{
		Name:        "fuzz",
		Aliases:     []string{"discovery", "traversal", "paths"},
		Description: "Directory and endpoint fuzzing, hidden backups, source disclosure, and path traversal",
		Modules: []string{
			"backup_archives", "devops_exposure", "debug_admin", "actuator", "cloud_takeover",
			"wordpress_fuzz", "git_recovery", "source_code_disclosure", "lfi", "open_redirect",
			"host_header", "host_poisoning", "smuggling", "cache_poisoning", "cache_deception",
		},
	},
}

// FindMode looks up a scan mode by its canonical name or alias (case-insensitive).
func FindMode(raw string) (ScanModeInfo, bool) {
	key := strings.ToLower(strings.TrimSpace(raw))
	for _, m := range AvailableModes {
		if strings.ToLower(m.Name) == key {
			return m, true
		}
		for _, a := range m.Aliases {
			if strings.ToLower(a) == key {
				return m, true
			}
		}
	}
	return ScanModeInfo{}, false
}

// ResolveScanModes parses a comma-separated mode string (e.g. "sql,xss,api")
// and returns the union of allowed vulnerability module names.
func ResolveScanModes(raw string) (allowedModules []string, isPassive bool, modeNames []string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.EqualFold(raw, "full") || strings.EqualFold(raw, "all") || strings.EqualFold(raw, "default") {
		return nil, false, []string{"Full Scan"}, nil
	}

	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '+'
	})

	moduleSet := make(map[string]struct{})
	isAllPassive := true
	hasFull := false

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		modeInfo, ok := FindMode(part)
		if !ok {
			var valid []string
			for _, m := range AvailableModes {
				valid = append(valid, m.Name)
			}
			return nil, false, nil, fmt.Errorf("unknown scan mode %q; valid modes are: %s", part, strings.Join(valid, ", "))
		}
		modeNames = append(modeNames, modeInfo.Name)
		if modeInfo.Name == "full" {
			hasFull = true
		}
		if !modeInfo.IsPassive {
			isAllPassive = false
		}
		for _, mod := range modeInfo.Modules {
			moduleSet[mod] = struct{}{}
		}
	}

	if hasFull {
		return nil, false, []string{"Full Scan"}, nil
	}

	for mod := range moduleSet {
		allowedModules = append(allowedModules, mod)
	}
	sort.Strings(allowedModules)
	return allowedModules, isAllPassive && len(modeNames) > 0, modeNames, nil
}

// ApplyScanModes configures a ScanConfig with the specified scan modes.
func ApplyScanModes(cfg *ScanConfig, modeStr string) error {
	allowed, isPassive, names, err := ResolveScanModes(modeStr)
	if err != nil {
		return err
	}
	cfg.AllowedVulnerabilityClasses = allowed
	cfg.PassiveMode = isPassive
	if len(names) > 0 {
		cfg.SmartScanProfile = strings.Join(names, "+")
	} else {
		cfg.SmartScanProfile = "Full Scan"
	}
	if isPassive {
		cfg.EnableFuzzing = false
		cfg.EnableOAST = false
		cfg.EnableWAFDetection = false
		cfg.Enable403BypassChecks = false
		cfg.EnableBusinessLogicChecks = false
		cfg.EnableRaceConditionTesting = false
		cfg.EnableSecondOrderTracking = false
		cfg.EnableHeadlessCrawler = false
		cfg.Explicit.EnableFuzzing = true
		cfg.Explicit.EnableOAST = true
		cfg.Explicit.EnableWAFDetection = true
		cfg.Explicit.Enable403BypassChecks = true
		cfg.Explicit.EnableBusinessLogicChecks = true
		cfg.Explicit.EnableRaceConditionTesting = true
		cfg.Explicit.EnableSecondOrderTracking = true
	}
	return nil
}
