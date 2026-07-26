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
