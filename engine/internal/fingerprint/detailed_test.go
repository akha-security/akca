package fingerprint_test

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/fingerprint"
	"github.com/akha-security/akca/engine/internal/models"
)

func TestEnrichFingerprintPHPVersion(t *testing.T) {
	fp := models.TechFingerprint{Host: "example.com", BackendLanguage: "PHP"}
	headers := map[string]string{
		"server":       "nginx/1.24.0",
		"x-powered-by": "PHP/8.2.12",
		"content-type": "text/html",
		"set-cookie":   "PHPSESSID=abc; path=/; HttpOnly",
	}
	body := `<html><head><title>Test Site</title><meta name="generator" content="WordPress 6.4.2"></head>
<script src="/wp-includes/js/jquery/jquery-3.7.1.min.js"></script></html>`

	fingerprint.EnrichFingerprint(&fp, 200, headers, body)

	if fp.BackendLanguage != "PHP/8.2.12" {
		t.Fatalf("backend=%q", fp.BackendLanguage)
	}
	if fp.PageTitle != "Test Site" {
		t.Fatalf("title=%q", fp.PageTitle)
	}
	if len(fp.Components) < 2 {
		t.Fatalf("expected components, got %+v", fp.Components)
	}
	foundPHP := false
	for _, c := range fp.Components {
		if c.Name == "PHP" && c.Version == "8.2.12" {
			foundPHP = true
		}
	}
	if !foundPHP {
		t.Fatalf("missing PHP version in components: %+v", fp.Components)
	}
	if fp.SecurityHeaders.PresentCount != 0 {
		t.Fatalf("expected zero security headers in minimal fixture, got %d", fp.SecurityHeaders.PresentCount)
	}
	if len(fp.SecurityHeaders.Missing) == 0 {
		t.Fatal("expected missing security headers list")
	}
	if len(fp.Cookies) != 1 || fp.Cookies[0].Name != "PHPSESSID" {
		t.Fatalf("cookies=%+v", fp.Cookies)
	}
}
