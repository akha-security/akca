package modules

import (
	"context"
	"errors"
	"testing"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

// withCNAME temporarily replaces the package-level DNS resolver seam and
// restores it after the test, so no test touches real DNS.
func withCNAME(t *testing.T, cname string, err error) {
	t.Helper()
	original := lookupCNAME
	lookupCNAME = func(context.Context, string) (string, error) { return cname, err }
	t.Cleanup(func() { lookupCNAME = original })
}

func TestCloudTakeoverConfirmedWhenCNAMEAndErrorBodyBothMatch(t *testing.T) {
	withCNAME(t, "dangling-bucket.s3.amazonaws.com.", nil)
	c := &activeTestClient{
		responses: map[string]httpclient.ResponseRecord{
			"GET https://sub.example.com/": {
				StatusCode: 404, Body: "<Error><Code>NoSuchBucket</Code></Error>",
				Headers: map[string]string{"Content-Type": "application/xml"},
			},
		},
	}

	r := newActiveRunner(t, c)
	target := ScanTarget{EndpointURL: "https://sub.example.com/", Method: "GET"}
	findings := r.runCloudTakeover(context.Background(), target)

	if len(findings) != 1 {
		t.Fatalf("expected one dangling CNAME finding, got %d", len(findings))
	}
	if findings[0].Severity != "high" {
		t.Fatalf("expected high severity, got %s", findings[0].Severity)
	}
	if findings[0].VulnClass != "cloud_takeover" {
		t.Fatalf("unexpected vuln class: %s", findings[0].VulnClass)
	}
}

func TestCloudTakeoverSafeNegativeWhenBodyDoesNotMatchProviderFingerprint(t *testing.T) {
	// CNAME points at a known takeover-prone provider, but the response body
	// is a normal, claimed resource: the provider error string is absent, so
	// this must not be reported as a takeover.
	withCNAME(t, "claimed-bucket.s3.amazonaws.com.", nil)
	c := &activeTestClient{
		responses: map[string]httpclient.ResponseRecord{
			"GET https://sub.example.com/": {
				StatusCode: 200, Body: "<html>Welcome to our site</html>",
				Headers: map[string]string{"Content-Type": "text/html"},
			},
		},
	}

	r := newActiveRunner(t, c)
	target := ScanTarget{EndpointURL: "https://sub.example.com/", Method: "GET"}
	findings := r.runCloudTakeover(context.Background(), target)

	if len(findings) != 0 {
		t.Fatalf("expected no finding for a claimed resource, got %d", len(findings))
	}
}

func TestCloudTakeoverNegativeWhenCNAMEDoesNotMatchAnyFingerprint(t *testing.T) {
	withCNAME(t, "internal.corp.example.net.", nil)
	c := &activeTestClient{
		responses: map[string]httpclient.ResponseRecord{
			"GET https://sub.example.com/": {
				StatusCode: 200, Body: "irrelevant",
			},
		},
	}

	r := newActiveRunner(t, c)
	target := ScanTarget{EndpointURL: "https://sub.example.com/", Method: "GET"}
	findings := r.runCloudTakeover(context.Background(), target)

	if len(findings) != 0 {
		t.Fatalf("expected no finding for an unrelated CNAME, got %d", len(findings))
	}
}

func TestCloudTakeoverNegativeWhenDNSLookupFails(t *testing.T) {
	withCNAME(t, "", errors.New("no such host"))
	c := &activeTestClient{responses: map[string]httpclient.ResponseRecord{}}

	r := newActiveRunner(t, c)
	target := ScanTarget{EndpointURL: "https://sub.example.com/", Method: "GET"}
	findings := r.runCloudTakeover(context.Background(), target)

	if len(findings) != 0 {
		t.Fatalf("expected no finding when DNS lookup fails, got %d", len(findings))
	}
}

func TestExtractHost(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"https with path", "https://sub.example.com/path?q=1", "sub.example.com"},
		{"http with port", "http://example.com:8080/", "example.com"},
		{"bare host", "example.com", "example.com"},
		{"host with port no scheme", "example.com:8443/admin", "example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractHost(tc.in); got != tc.want {
				t.Fatalf("extractHost(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
