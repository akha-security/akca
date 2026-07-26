package crawler

import (
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
)

func TestNormalizeURLAndRouteTemplate(t *testing.T) {
	norm, err := NormalizeURL("HTTPS://Example.com/path/?b=2&a=1#frag")
	if err != nil {
		t.Fatal(err)
	}
	if norm != "https://example.com/path?a=1&b=2" {
		t.Fatalf("normalize=%q", norm)
	}

	route := NormalizeRouteTemplate("/users/{id}/posts/[slug]/view/:name")
	if route != "/users/:id/posts/:id/view/:id" {
		t.Fatalf("route=%q", route)
	}
}

func TestCrawlerTrapAvoidance(t *testing.T) {
	traps := []string{
		"https://example.com/calendar/2024/05/day",
		"https://example.com/search?filter=color&facet=size&sort=price&page=999",
	}
	for _, u := range traps {
		if !IsCrawlerTrap(u) {
			t.Fatalf("expected trap: %s", u)
		}
	}
	if IsCrawlerTrap("https://example.com/api/users") {
		t.Fatal("api path should not be trap")
	}
}

func TestRuntimeCoverageCountsUniqueInstrumentedEndpoints(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/runtime-coverage.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureScan("runtime-coverage"); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"example.test"}
	c := New("runtime-coverage", cfg, nil, scope.NewEngine(cfg), db, func(string, string, map[string]interface{}) error {
		return nil
	})
	response := &RequestTemplate{ResponseStatus: 200}
	c.recordEndpoint("https://example.test/api/me", "GET", SourceBrowserXHR, 1, 0, "runtime", response)
	c.recordEndpoint("https://example.test/api/me", "GET", SourceBrowserXHR, 1, 0, "duplicate", response)
	c.recordEndpoint("https://example.test/static/app.js", "GET", SourceScript, 1, 0, "static", response)
	if got := c.RuntimeCoverage(); got != 1 {
		t.Fatalf("runtime endpoint coverage = %d, want 1", got)
	}
}

func TestGraphIdentityUsesNonSecretAuthProfileID(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.AuthProfiles = []config.AuthProfile{{
		ID:      "low-role",
		Headers: map[string]string{"Authorization": "Bearer must-not-appear"},
	}}
	c := &Crawler{cfg: cfg}
	if got := c.graphIdentity(); got != "auth_profile:low-role" {
		t.Fatalf("graph identity = %q", got)
	}
	if strings.Contains(c.graphIdentity(), "must-not-appear") {
		t.Fatal("graph identity leaked credentials")
	}
}

func TestPriorityScoring(t *testing.T) {
	high := ScoreEndpoint(DiscoveredEndpoint{URL: "https://example.com/api/admin", Source: SourceGraphQL, Confidence: 0.9})
	low := ScoreEndpoint(DiscoveredEndpoint{URL: "https://example.com/static/app.js", Source: SourceScript, Confidence: 0.5})
	if high <= low {
		t.Fatalf("high=%d low=%d", high, low)
	}
}

func TestJSBundleAndSPARouteExtraction(t *testing.T) {
	js := `
fetch("/api/v1/users");
axios.post("/graphql");
const routes = ["/users/:id", "/orders/{orderId}"];
__NEXT_DATA__ = {"props":{"pageProps":{}},"pathname":"/dashboard"};
new WebSocket("wss://example.com/live");
`
	eps := ExtractFromJSBundle("https://example.com/app.js", js)
	if len(eps) < 4 {
		t.Fatalf("expected multiple endpoints, got %d", len(eps))
	}
	foundGraphQL := false
	foundAxiosPost := false
	for _, ep := range eps {
		if ep.Source == SourceGraphQL {
			foundGraphQL = true
		}
		if strings.Contains(ep.URL, "/graphql") && ep.Method == "POST" {
			foundAxiosPost = true
		}
	}
	if !foundGraphQL {
		t.Fatal("expected graphql endpoint")
	}
	if !foundAxiosPost {
		t.Fatal("expected axios.post to register POST method")
	}
}

func TestAPIDocsDiscovery(t *testing.T) {
	eps := CommonAPIDocPaths("https://example.com")
	if len(eps) < 5 {
		t.Fatalf("expected api doc paths, got %d", len(eps))
	}
}

func TestHTMLExtractionSources(t *testing.T) {
	html := `<html>
<a href="/login">Login</a>
<form action="/submit" method="post"><input name="token" value="abc"></form>
<link rel="canonical" href="https://example.com/home">
<script src="/static/main.js"></script>
<!-- https://example.com/hidden -->
</html>`
	eps := ExtractFromHTML("https://example.com/", html)
	if len(eps) < 4 {
		t.Fatalf("expected html extractions, got %v", eps)
	}
	foundFormPOST := false
	for _, ep := range eps {
		if ep.Source == SourceForm && ep.Method == "POST" {
			foundFormPOST = true
			if ep.RequestTemplate == nil || !strings.Contains(ep.RequestTemplate.Body, "token=abc") {
				t.Fatalf("form template=%+v", ep.RequestTemplate)
			}
		}
	}
	if !foundFormPOST {
		t.Fatal("expected POST form with body template")
	}
}
