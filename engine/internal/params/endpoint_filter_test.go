package params

import (
	"net/http"
	"testing"

	"github.com/akha-security/akca/engine/internal/storage"
)

func TestShouldDiscoverEndpointSkipsStatic(t *testing.T) {
	if ShouldDiscoverEndpoint("https://example.com/app.js", "GET") {
		t.Fatal("expected static js to skip")
	}
	if !ShouldDiscoverEndpoint("https://example.com/api/users", "GET") {
		t.Fatal("expected api endpoint to probe")
	}
}

func TestShouldDiscoverEndpointSkipsDiscoveryDocuments(t *testing.T) {
	for _, rawURL := range []string{
		"https://example.com/robots.txt",
		"https://example.com/app/robots.txt?cache=1",
		"https://example.com/sitemap.xml",
		"https://example.com/sitemap-index.xml",
		"https://example.com/.well-known/openid-configuration",
		"https://example.com/.well-known/jwks.json",
	} {
		if ShouldDiscoverEndpoint(rawURL, http.MethodGet) {
			t.Fatalf("discovery document should not receive hidden-parameter probes: %s", rawURL)
		}
	}
	if !ShouldDiscoverEndpoint("https://example.com/api/.well-known-user", http.MethodGet) {
		t.Fatal("ordinary API route containing a similar token was over-filtered")
	}
}

func TestDifferentialWordlistCap(t *testing.T) {
	wl := DifferentialWordlist("https://example.com/search", 20)
	if len(wl) != 20 {
		t.Fatalf("expected cap 20, got %d", len(wl))
	}
	if wl[0] != "q" && wl[0] != "id" {
		t.Fatalf("expected prioritized names first, got %q", wl[0])
	}
}

func TestPassiveEnoughForSkip(t *testing.T) {
	passive := []DiscoveredParameter{
		{Priority: 95}, {Priority: 95}, {Priority: 95}, {Priority: 80},
		{Priority: 80}, {Priority: 80}, {Priority: 80}, {Priority: 80},
	}
	if !PassiveEnoughForSkip(passive, http.MethodGet) {
		t.Fatal("expected skip with 4 passive params on GET")
	}
	if PassiveEnoughForSkip(passive, http.MethodPost) {
		t.Fatal("POST endpoints should never skip active probing")
	}
}

func TestSelectDiscoveryEndpointsSkipsContentPagesAndDeduplicatesURLShapes(t *testing.T) {
	all := []storage.DiscoveryEndpoint{
		{ID: 1, URL: "https://example.com/about", Method: http.MethodGet},
		{ID: 2, URL: "https://example.com/page?id=1", Method: http.MethodGet},
		{ID: 3, URL: "https://example.com/page?id=2", Method: http.MethodGet},
		{ID: 4, URL: "https://example.com/page?id=2&lang=tr", Method: http.MethodGet},
		{ID: 5, URL: "https://example.com/api/users/123", Method: http.MethodGet},
		{ID: 6, URL: "https://example.com/api/users/456", Method: http.MethodGet},
		{ID: 7, URL: "https://example.com/orders", Method: http.MethodPost},
	}

	got, stats := selectDiscoveryEndpoints(all, 20)
	if len(got) != 4 {
		t.Fatalf("selected=%d want 4: %+v", len(got), got)
	}
	if stats.SkippedLowValue != 1 || stats.SkippedDuplicate != 2 || stats.SkippedByLimit != 0 {
		t.Fatalf("unexpected selection stats: %+v", stats)
	}
	for _, endpoint := range got {
		if endpoint.URL == "https://example.com/about" || endpoint.URL == "https://example.com/page?id=2" ||
			endpoint.URL == "https://example.com/api/users/456" {
			t.Fatalf("redundant or low-value endpoint selected: %+v", endpoint)
		}
	}
}

func TestSelectDiscoveryEndpointsHonorsIndependentLimit(t *testing.T) {
	all := []storage.DiscoveryEndpoint{
		{ID: 1, URL: "https://a.example/api/one", Method: http.MethodGet},
		{ID: 2, URL: "https://a.example/api/two", Method: http.MethodGet},
		{ID: 3, URL: "https://a.example/api/three", Method: http.MethodGet},
	}
	got, stats := selectDiscoveryEndpoints(all, 2)
	if len(got) != 2 || stats.SkippedByLimit != 1 {
		t.Fatalf("selected=%d stats=%+v", len(got), stats)
	}
}
