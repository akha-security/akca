package subdomain

import (
	"context"
	"testing"
	"time"
)

func TestSanitizeDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"http://example.com", "example.com"},
		{"https://www.example.com/path?q=1", "example.com"},
		{"sub.domain.co.uk:8080", "sub.domain.co.uk"},
		{"  EXAMPLE.COM  ", "example.com"},
	}

	for _, tt := range tests {
		got := sanitizeDomain(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeDomain(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestIsValidHostname(t *testing.T) {
	if !isValidHostname("sub.example.com") {
		t.Errorf("expected valid hostname")
	}
	if isValidHostname("invalid_host_no_tld") {
		t.Errorf("expected invalid hostname")
	}
}

func TestBelongsToRootDomainRequiresLabelBoundary(t *testing.T) {
	if !belongsToRootDomain("api.example.com", "example.com") {
		t.Fatal("subdomain should belong to its root domain")
	}
	if belongsToRootDomain("notexample.com", "example.com") {
		t.Fatal("suffix-only lookalike must not belong to root domain")
	}
}

func TestSubdomainEngineInstantiation(t *testing.T) {
	eng := New()
	if eng == nil {
		t.Fatal("expected non-nil Subdomain Engine")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Probing invalid domain should fail gracefully without panic
	_, liveURLs, err := eng.DiscoverAndProbe(ctx, "invalid-non-existent-domain-test12345.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = liveURLs
}
