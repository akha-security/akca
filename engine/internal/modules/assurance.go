package modules

import (
	"fmt"
	"sort"
	"strings"
)

// ModuleAssuranceProfile is the machine-readable coverage contract for a
// runnable module. It does not claim that a vulnerability was tested; it tells
// the planner, report and release gate what must be observable before coverage
// can be considered meaningful.
type ModuleAssuranceProfile struct {
	Module               string   `json:"module"`
	Family               string   `json:"family"`
	Standards            []string `json:"standards"`
	RequiredCapabilities []string `json:"required_capabilities,omitempty"`
	OptionalCapabilities []string `json:"optional_capabilities,omitempty"`
	RequiredSurfaces     []string `json:"required_surfaces,omitempty"`
	BenchmarkContracts   []string `json:"benchmark_contracts"`
}

func AssuranceProfile(module string) ModuleAssuranceProfile {
	module = strings.ToLower(strings.TrimSpace(module))
	profile := ModuleAssuranceProfile{
		Module: module, Family: ModuleCategory(module),
		Standards:          []string{"OWASP-ASVS-v5.0.0"},
		BenchmarkContracts: []string{"vulnerable", "patched", "misleading-control", "capability-gap"},
	}
	switch profile.Family {
	case "injection":
		profile.Standards = append(profile.Standards, "OWASP-WSTG-INPV")
		profile.RequiredSurfaces = []string{"query", "form", "json", "xml", "multipart", "header", "cookie", "path"}
	case "serverside":
		profile.Standards = append(profile.Standards, "OWASP-WSTG-CONF", "OWASP-WSTG-INPV")
		profile.RequiredSurfaces = []string{"endpoint", "query", "json", "xml", "header", "path"}
	case "logic_auth":
		profile.Standards = append(profile.Standards, "OWASP-WSTG-ATHN", "OWASP-WSTG-ATHZ", "OWASP-WSTG-SESS", "OWASP-WSTG-BUSL")
		profile.RequiredSurfaces = []string{"anonymous", "authenticated", "role-a", "role-b", "state-before", "state-after"}
	default:
		profile.Standards = append(profile.Standards, "OWASP-WSTG-CLNT", "OWASP-WSTG-INFO", "OWASP-WSTG-CONF")
		profile.RequiredSurfaces = []string{"endpoint", "browser", "header", "script", "schema"}
	}
	applyAPISecurityMapping(&profile)
	applyCapabilityContract(&profile)
	profile.Standards = uniqueSorted(profile.Standards)
	profile.RequiredCapabilities = uniqueSorted(profile.RequiredCapabilities)
	profile.OptionalCapabilities = uniqueSorted(profile.OptionalCapabilities)
	return profile
}

func applyAPISecurityMapping(profile *ModuleAssuranceProfile) {
	api := func(id string) { profile.Standards = append(profile.Standards, "OWASP-API-2023-"+id) }
	switch profile.Module {
	case "idor", "tenant_isolation":
		api("API1-BOLA")
	case "broken_auth", "improper_auth", "jwt", "oauth", "oauth_flow_audit", "account_enum", "account_recovery", "session_lifecycle":
		api("API2-BROKEN-AUTH")
	case "mass_assignment", "api_exposure", "sensitive_data":
		api("API3-BOPLA")
	case "rate_limit", "cpdos", "graphql", "grpc_scan", "file_upload":
		api("API4-RESOURCE-CONSUMPTION")
	case "bfla", "route_auth_bypass", "http_methods":
		api("API5-BFLA")
	case "business_logic", "race_condition", "race_condition_sync", "hpp":
		api("API6-SENSITIVE-FLOWS")
	case "ssrf":
		api("API7-SSRF")
	case "security_headers", "cookie_security", "tls_misconfig", "cors", "debug_admin", "swagger_exposure", "framework_debug":
		api("API8-MISCONFIGURATION")
	case "api_versioning", "shadow_api", "script_source", "source_code_disclosure":
		api("API9-INVENTORY")
	case "webhook_security", "cloud_storage", "cloud_posture", "saas_exposure", "llm_injection":
		api("API10-UNSAFE-CONSUMPTION")
	}
}

func applyCapabilityContract(profile *ModuleAssuranceProfile) {
	switch profile.Module {
	case "blind_xss":
		profile.RequiredCapabilities = append(profile.RequiredCapabilities, "oast")
	case "csti_detection", "client_ssti", "jsonp_callback", "ws_cswsh":
		profile.RequiredCapabilities = append(profile.RequiredCapabilities, "browser")
	case "idor", "tenant_isolation":
		profile.RequiredCapabilities = append(profile.RequiredCapabilities, "two_roles", "ownership_policy")
	case "bfla":
		profile.RequiredCapabilities = append(profile.RequiredCapabilities, "two_roles", "authorization_policy", "cleanup")
	case "business_logic", "race_condition", "race_condition_sync", "account_recovery", "webhook_security", "csrf", "session_lifecycle", "file_upload", "cache_deception", "hpp":
		profile.RequiredCapabilities = append(profile.RequiredCapabilities, "workflow_policy", "state_observation", "cleanup")
	}
	switch profile.Module {
	case "xss", "second_order":
		profile.OptionalCapabilities = append(profile.OptionalCapabilities, "browser", "oast")
	case "sqli", "ssti", "command_injection", "ssrf", "xxe", "insecure_deserialization", "pdf_injection", "server_side_js_injection", "llm_injection":
		profile.OptionalCapabilities = append(profile.OptionalCapabilities, "oast", "runtime_sensor")
	}
}

func AllAssuranceProfiles() []ModuleAssuranceProfile {
	modules := ModuleCatalog()
	out := make([]ModuleAssuranceProfile, 0, len(modules))
	for _, module := range modules {
		out = append(out, AssuranceProfile(module))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Module < out[j].Module })
	return out
}

func ValidateAssuranceProfiles() error {
	seen := make(map[string]struct{})
	for _, profile := range AllAssuranceProfiles() {
		if profile.Module == "" || profile.Family == "" || len(profile.Standards) < 2 || len(profile.BenchmarkContracts) != 4 {
			return fmt.Errorf("incomplete assurance profile for %q", profile.Module)
		}
		if _, duplicate := seen[profile.Module]; duplicate {
			return fmt.Errorf("duplicate assurance profile for %s", profile.Module)
		}
		seen[profile.Module] = struct{}{}
	}
	if len(seen) != len(ModuleCatalog()) {
		return fmt.Errorf("assurance profile count %d does not match module catalog %d", len(seen), len(ModuleCatalog()))
	}
	return nil
}

func uniqueSorted(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if item = strings.TrimSpace(item); item != "" {
			if _, ok := seen[item]; !ok {
				seen[item] = struct{}{}
				out = append(out, item)
			}
		}
	}
	sort.Strings(out)
	return out
}
