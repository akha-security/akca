package modules

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

func TestSecurityHeadersReportsEffectiveUnsafeCSP(t *testing.T) {
	r := newActiveRunner(t, &activeDynamicClient{handler: func(string, string, map[string]string) httpclient.ResponseRecord {
		return httpclient.ResponseRecord{StatusCode: 200, Body: "normal page content", Headers: map[string]string{
			"Content-Security-Policy":   "default-src 'self'; script-src 'self' 'unsafe-inline'",
			"X-Frame-Options":           "DENY",
			"X-Content-Type-Options":    "nosniff",
			"Strict-Transport-Security": "max-age=31536000",
			"Referrer-Policy":           "strict-origin-when-cross-origin",
			"Permissions-Policy":        "geolocation=()",
		}}
	}})
	findings := r.runSecurityHeaders(context.Background(), ScanTarget{EndpointURL: "https://example.com/", Method: "GET"})
	if !hasSignal(findings, "csp_unsafe_inline_script") {
		t.Fatalf("expected unsafe CSP finding, got %+v", findings)
	}
}

func TestSecurityHeadersDetectsValidatedChromeLoggerAndWeakCOOP(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(`{"version":"4.1","columns":["log"],"rows":[[{"password":"debug"}]]}`))
	r := newActiveRunner(t, &activeDynamicClient{handler: func(string, string, map[string]string) httpclient.ResponseRecord {
		return httpclient.ResponseRecord{StatusCode: 200, Body: "normal page content", Headers: map[string]string{
			"Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "DENY",
			"X-Content-Type-Options": "nosniff", "Strict-Transport-Security": "max-age=31536000",
			"Referrer-Policy": "strict-origin", "Permissions-Policy": "geolocation=()",
			"Cross-Origin-Opener-Policy": "unsafe-none", "X-ChromeLogger-Data": encoded,
		}}
	}})
	findings := r.runSecurityHeaders(context.Background(), ScanTarget{EndpointURL: "https://example.com/", Method: "GET"})
	if !hasSignal(findings, "weak_coop") || !hasSignal(findings, "chrome_logger_disclosure") {
		t.Fatalf("expected COOP and Chrome Logger findings, got %+v", findings)
	}
}

func TestChromeLoggerRejectsUnstructuredHeader(t *testing.T) {
	if chromeLoggerDisclosure("not-base64-or-json") {
		t.Fatal("unstructured header must not be treated as Chrome Logger data")
	}
}

func TestSecurityHeadersDoesNotReportNeutralizedUnsafeInline(t *testing.T) {
	policy := "default-src 'self'; script-src 'self' 'nonce-abc123' 'strict-dynamic' 'unsafe-inline'"
	if weaknesses := weakCSPDirectives(policy); hasCSPWeakness(weaknesses, "csp_unsafe_inline_script") {
		t.Fatalf("nonce-protected CSP must not report ineffective unsafe-inline: %+v", weaknesses)
	}
}

func hasSignal(findings []ModuleFinding, signal string) bool {
	for _, finding := range findings {
		if finding.Evidence.Signal == signal {
			return true
		}
	}
	return false
}

func hasCSPWeakness(weaknesses []cspWeakness, signal string) bool {
	for _, weakness := range weaknesses {
		if weakness.signal == signal {
			return true
		}
	}
	return false
}
