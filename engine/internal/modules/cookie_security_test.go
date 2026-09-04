package modules

import (
	"context"
	"net/url"
	"testing"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

func TestCookieSecurityDetection(t *testing.T) {
	cases := []struct {
		name         string
		url          string
		setCookie    string
		expectSignal string
	}{
		{
			name:         "HTTPS session cookie missing Secure",
			url:          "https://example.com/login",
			setCookie:    "PHPSESSID=abc12345; Path=/; HttpOnly",
			expectSignal: "cookie_missing_secure",
		},
		{
			name:         "Session cookie missing HttpOnly",
			url:          "https://example.com/login",
			setCookie:    "session_id=xyz987; Path=/; Secure",
			expectSignal: "cookie_missing_httponly",
		},
		{
			name:         "__Host- prefix rule violation with domain",
			url:          "https://example.com/",
			setCookie:    "__Host-id=123; Secure; Path=/; Domain=example.com",
			expectSignal: "cookie_host_prefix_violation",
		},
		{
			name:         "__Secure- prefix missing Secure",
			url:          "https://example.com/",
			setCookie:    "__Secure-token=abc; Path=/",
			expectSignal: "cookie_secure_prefix_violation",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, _ := url.Parse(tc.url)
			path := u.Path
			if path == "" {
				path = "/"
			}
			c := &groupDClient{
				responses: map[string]string{
					"__default__": "ok",
					path:          "ok",
				},
				headers: map[string]map[string]string{
					"__default__": {
						"Set-Cookie": tc.setCookie,
					},
					path: {
						"Set-Cookie": tc.setCookie,
					},
				},
			}
			r := groupDRunner(t, c)

			target := ScanTarget{EndpointURL: tc.url, Method: "GET"}
			findings := r.runCookieSecurity(context.Background(), target)

			found := false
			for _, f := range findings {
				if f.Evidence.Signal == tc.expectSignal {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected finding signal %q for Set-Cookie %q, got findings: %+v", tc.expectSignal, tc.setCookie, findings)
			}
		})
	}
}

func TestCookieAndSecurityHeaderDeduplication(t *testing.T) {
	// Test that multiple crawled URLs on the same host do NOT duplicate cookie or security header findings
	urls := []string{
		"https://example.com/",
		"https://example.com/products",
		"https://example.com/about",
		"https://example.com/contact",
		"https://example.com/user/123",
	}

	c := &activeDynamicClient{
		handler: func(method, rawURL string, headers map[string]string) httpclient.ResponseRecord {
			return httpclient.ResponseRecord{
				StatusCode: 200,
				Body:       "<html>Page</html>",
				Headers: map[string]string{
					"Set-Cookie": "PHPSESSID=session12345; Path=/; Secure",
				},
			}
		},
	}
	r := newActiveRunner(t, c)

	totalCookieFindings := 0
	totalSecurityHeaderFindings := 0

	for _, u := range urls {
		target := ScanTarget{EndpointURL: u, Method: "GET"}
		cFindings := r.runCookieSecurity(context.Background(), target)
		totalCookieFindings += len(cFindings)

		hFindings := r.runSecurityHeaders(context.Background(), target)
		totalSecurityHeaderFindings += len(hFindings)
	}

	// For PHPSESSID with missing HttpOnly and missing SameSite, exactly 2 distinct findings
	// (1 for missing HttpOnly, 1 for weak SameSite) must be emitted across all 5 URLs instead of 10
	if totalCookieFindings != 2 {
		t.Fatalf("expected exactly 2 distinct cookie findings across 5 URLs on the same domain, got %d", totalCookieFindings)
	}

	// For security headers on example.com, it must only run on the first URL and produce 0 on subsequent 4 URLs
	if totalSecurityHeaderFindings == 0 {
		t.Fatalf("expected security header findings on the domain, got 0")
	}

	// 6th URL on the same domain must produce 0 additional findings
	target6 := ScanTarget{EndpointURL: "https://example.com/extra-page", Method: "GET"}
	if extra := r.runSecurityHeaders(context.Background(), target6); len(extra) != 0 {
		t.Fatalf("expected 0 security header findings on 6th URL (deduplicated), got %d", len(extra))
	}
	if extra := r.runCookieSecurity(context.Background(), target6); len(extra) != 0 {
		t.Fatalf("expected 0 cookie findings on 6th URL (deduplicated), got %d", len(extra))
	}
}

func TestRunSingleModuleDoesNotConsumeCookieGuardTwice(t *testing.T) {
	c := &activeDynamicClient{handler: func(method, rawURL string, headers map[string]string) httpclient.ResponseRecord {
		return httpclient.ResponseRecord{
			StatusCode: 200,
			Body:       "normal page",
			Headers:    map[string]string{"Set-Cookie": "session_id=abc123; Path=/; Secure"},
		}
	}}
	r := newActiveRunner(t, c)
	target := ScanTarget{EndpointURL: "https://example.com/", Method: "GET"}
	if findings := r.runSingleModule(context.Background(), "cookie_security", target); len(findings) == 0 {
		t.Fatal("single-module dispatcher consumed the endpoint guard before cookie module execution")
	}
	if findings := r.runSingleModule(context.Background(), "cookie_security", target); len(findings) != 0 {
		t.Fatalf("cookie module should remain origin-deduplicated, got %d additional findings", len(findings))
	}
}
