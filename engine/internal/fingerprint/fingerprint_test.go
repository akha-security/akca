package fingerprint

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/models"
)

func TestTechFingerprintHints(t *testing.T) {
	headers := map[string]string{
		"server":       "nginx",
		"x-powered-by": "PHP/8.2",
	}
	body := `<html><script src="/_next/static/chunks/main.js"></script><meta name="csrf-token" content="x"></html>`
	combined := headersText(normalizeHeaders(headers)) + "\n" + body

	fp := models.TechFingerprint{}
	fp.ServerCDN = detectServerCDN(normalizeHeaders(headers), combined)
	fp.BackendLanguage = detectBackend(normalizeHeaders(headers), combined)
	fp.Framework = detectFramework(normalizeHeaders(headers), combined)
	fp.JSFramework = detectJSFramework(combined)
	fp.Hints = collectHints(fp)

	if fp.BackendLanguage == "" {
		t.Fatal("expected backend language")
	}
	if fp.JSFramework != "React" {
		t.Fatalf("expected React, got %q", fp.JSFramework)
	}
	if len(fp.Hints) == 0 {
		t.Fatal("expected hints")
	}
}

func TestEndpointIntelligenceRecommendation(t *testing.T) {
	waf := &models.WAFProfile{CautiousModeRecommended: false}
	tech := &models.TechFingerprint{Framework: "Laravel", BackendLanguage: "PHP"}
	intel := ClassifyEndpoint("https://api.example.com/v1/users", "POST", "application/json", `{}`, waf, tech)

	if intel.EndpointType != "api" {
		t.Fatalf("endpoint type=%q", intel.EndpointType)
	}
	if !intel.StateChanging {
		t.Fatal("POST should be state-changing")
	}
	found := false
	for _, m := range intel.RecommendedModules {
		if m == "sqli" || m == "idor" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected api modules, got %v", intel.RecommendedModules)
	}
}

func TestWAFProtectedRecommendationKeepsAllCapabilities(t *testing.T) {
	waf := &models.WAFProfile{CautiousModeRecommended: true, Vendor: "Cloudflare"}
	intel := ClassifyEndpoint("https://example.com/page", "GET", "text/html", "<form></form>", waf, nil)
	found := false
	for _, m := range intel.RecommendedModules {
		if m == "xss" {
			found = true
		}
	}
	if !found {
		t.Fatalf("WAF pacing must not remove xss capability, got %v", intel.RecommendedModules)
	}
}
