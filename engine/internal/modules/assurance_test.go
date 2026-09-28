package modules

import "testing"

func TestEveryRunnableModuleHasAnAssuranceContract(t *testing.T) {
	if err := ValidateAssuranceProfiles(); err != nil {
		t.Fatal(err)
	}
	profiles := AllAssuranceProfiles()
	if len(profiles) != len(ModuleCatalog()) {
		t.Fatalf("profiles=%d modules=%d", len(profiles), len(ModuleCatalog()))
	}
}

func TestHighRiskCapabilitiesAndAPICategoriesAreExplicit(t *testing.T) {
	tests := map[string][]string{
		"idor":             {"OWASP-API-2023-API1-BOLA", "two_roles", "ownership_policy"},
		"rate_limit":       {"OWASP-API-2023-API4-RESOURCE-CONSUMPTION"},
		"business_logic":   {"OWASP-API-2023-API6-SENSITIVE-FLOWS", "workflow_policy", "cleanup"},
		"webhook_security": {"OWASP-API-2023-API10-UNSAFE-CONSUMPTION"},
		"blind_xss":        {"oast"},
	}
	for module, expected := range tests {
		profile := AssuranceProfile(module)
		all := append(append([]string{}, profile.Standards...), profile.RequiredCapabilities...)
		for _, want := range expected {
			found := false
			for _, value := range all {
				found = found || value == want
			}
			if !found {
				t.Errorf("%s assurance profile missing %s: %+v", module, want, profile)
			}
		}
	}
}
