package report

import "testing"

func TestTaxonomyForCoreFindings(t *testing.T) {
	tests := []struct{ class, cwe, owasp string }{
		{"sqli", "CWE-89", "A05:2025 Injection"},
		{"idor", "CWE-862", "A01:2025 Broken Access Control"},
		{"vulnerable_components", "CWE-1104", "A03:2025 Software Supply Chain Failures"},
		{"security_headers", "CWE-16", "A02:2025 Security Misconfiguration"},
	}
	for _, tt := range tests {
		cwe, owasp := taxonomyFor(tt.class, "")
		if len(cwe) == 0 || cwe[0] != tt.cwe || len(owasp) == 0 || owasp[0] != tt.owasp {
			t.Fatalf("%s => %v %v", tt.class, cwe, owasp)
		}
	}
}

func TestTaxonomyLeavesUnknownExtensionUnclassified(t *testing.T) {
	cwe, owasp := taxonomyFor("custom_plugin_result", "")
	if len(cwe) != 0 || len(owasp) != 0 {
		t.Fatalf("custom module must not be guessed: %v %v", cwe, owasp)
	}
}
