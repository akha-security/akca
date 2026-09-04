package scope

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
)

func TestScopeEngineRules(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"example.com", "api.example.com"}
	cfg.ExcludeDomains = []string{"blocked.example.com"}
	cfg.ExcludedPaths = []string{"/admin/*", "/logout"}

	e := NewEngine(cfg)

	cases := []struct {
		url    string
		scope  bool
		reason string
	}{
		{"https://api.example.com/path", true, "in scope"},
		{"https://blocked.example.com/", false, "host"},
		{"https://other.com/", false, "not in include"},
		{"https://example.com/admin/settings", false, "path"},
	}
	for _, c := range cases {
		got := e.IsInScope(c.url)
		if got != c.scope {
			t.Fatalf("%s scope=%v want %v explain=%s", c.url, got, c.scope, e.Explain(c.url))
		}
		if c.scope && !e.CanActivelyTest(c.url) {
			t.Fatalf("actively test should match in-scope url")
		}
	}
}

func TestWildcardIncludeRule(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"*.example.com"}
	e := NewEngine(cfg)
	if !e.IsInScope("https://dev.example.com/") {
		t.Fatal("expected wildcard include")
	}
}

func TestURLLikeIncludeDomainAndUnsupportedScheme(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"https://Example.com:443/path?q=1"}
	e := NewEngine(cfg)
	if !e.IsInScope("https://example.com/login") {
		t.Fatal("expected URL-like include domain to normalize to host")
	}
	if e.IsInScope("ftp://example.com/file") {
		t.Fatal("unsupported schemes must not be in active scope")
	}
}

func TestScopePortEnforcement(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{
		"localhost:8088",
		"https://example.com:8443",
		"[::1]:8080",
	}
	e := NewEngine(cfg)

	cases := []struct {
		url      string
		expected bool
	}{
		{"http://localhost:8088/api", true},
		{"http://localhost:8089/api", false},
		{"http://localhost/api", false},
		{"https://example.com:8443/test", true},
		{"https://example.com:443/test", false},
		{"https://example.com/test", false},
		{"http://[::1]:8080/path", true},
		{"http://[::1]:3000/path", false},
	}

	for _, c := range cases {
		got := e.IsInScope(c.url)
		if got != c.expected {
			t.Fatalf("url %s got %v, want %v (explain: %s)", c.url, got, c.expected, e.Explain(c.url))
		}
	}
}

func TestLinkedAPIScopeExpansionIsOptIn(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"www.example.com"}
	e := NewEngine(cfg)

	cases := []struct {
		url      string
		expected bool
	}{
		{"https://www.example.com/home", true},
		{"https://api.example.com/v1/users", false},
		{"https://auth.example.com/oauth/token", false},
		{"https://backend.example.com/graphql", false},
		{"https://app.example.com/dashboard", false},
		{"https://otherdomain.com/api", false},
		{"https://evil.com/", false},
	}

	for _, c := range cases {
		got := e.IsInScope(c.url)
		if got != c.expected {
			t.Fatalf("url %s got %v, want %v (explain: %s)", c.url, got, c.expected, e.Explain(c.url))
		}
	}

	cfg.IncludeLinkedAPISubdomains = true
	e = NewEngine(cfg)
	for _, rawURL := range []string{
		"https://api.example.com/v1/users",
		"https://auth.example.com/oauth/token",
		"https://backend.example.com/graphql",
		"https://app.example.com/dashboard",
	} {
		if !e.IsInScope(rawURL) {
			t.Fatalf("expected linked API host to be in scope when opt-in is enabled: %s", rawURL)
		}
	}
}

func TestAdoptHost(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"start.example.com"}
	e := NewEngine(cfg)

	if e.IsInScope("https://relocated.otherapp.com/login") {
		t.Fatal("unrelated host should not be in scope before adoption")
	}

	e.AdoptHost("relocated.otherapp.com")

	if !e.IsInScope("https://relocated.otherapp.com/login") {
		t.Fatal("adopted host should be in scope after AdoptHost")
	}
}

func TestPublicSuffixRootDomainAndMultiTenantIsolation(t *testing.T) {
	// Multi-part ccTLDs / institutional domains must NOT collapse to same root
	if SameRootDomain("izmirokulu.k12.tr", "ankaraokulu.k12.tr") {
		t.Fatal("distinct k12.tr tenants must not share root domain")
	}
	if SameRootDomain("tenant1.github.io", "tenant2.github.io") {
		t.Fatal("distinct github.io users must not share root domain")
	}
	if SameRootDomain("bucket1.s3.amazonaws.com", "bucket2.s3.amazonaws.com") {
		t.Fatal("distinct S3 buckets must not share root domain")
	}

	// Legitimate multi-part domains must collapse correctly
	if !SameRootDomain("api.example.co.uk", "www.example.co.uk") {
		t.Fatal("subdomains on co.uk should share root domain")
	}
	if !SameRootDomain("auth.company.com.tr", "company.com.tr") {
		t.Fatal("subdomains on com.tr should share root domain")
	}
}

func TestIsLinkedAPISubdomainEnforcesPrefixes(t *testing.T) {
	base := "example.com"
	if !IsLinkedAPISubdomain("api.example.com", base) {
		t.Fatal("api.example.com should be allowed as linked API")
	}
	if !IsLinkedAPISubdomain("auth.example.com", base) {
		t.Fatal("auth.example.com should be allowed as linked API")
	}
	if !IsLinkedAPISubdomain("backend.example.com", base) {
		t.Fatal("backend.example.com should be allowed as linked API")
	}
	// Arbitrary non-API sibling subdomains must NOT be automatically linked
	if IsLinkedAPISubdomain("random-marketing.example.com", base) {
		t.Fatal("random-marketing.example.com should not be allowed as linked API")
	}
	if IsLinkedAPISubdomain("blog.example.com", base) {
		t.Fatal("blog.example.com should not be allowed as linked API")
	}
}
