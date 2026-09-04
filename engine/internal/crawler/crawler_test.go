package crawler

import (
	"fmt"
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
	if route != "/users/{id}/posts/{slug}/view/{name}" {
		t.Fatalf("route=%q", route)
	}

	fingerprint := StructuralRouteFingerprint(route)
	if fingerprint != "/users/:param/posts/:param/view/:param" {
		t.Fatalf("fingerprint=%q", fingerprint)
	}
}

func TestCrawlerTrapUsesSameRouteCombinationGrowth(t *testing.T) {
	c := &Crawler{queryVariants: make(map[string]map[string]struct{})}
	for i := 0; i < maxRouteQueryVariants; i++ {
		raw := fmt.Sprintf("https://example.com/filter?category=item-%d", i)
		if !c.acceptQueryVariantLocked(raw, "GET") {
			t.Fatalf("variant %d was rejected before route cap", i)
		}
	}
	if c.acceptQueryVariantLocked("https://example.com/filter?category=overflow", "GET") {
		t.Fatal("same-route combinatorial overflow should be rejected")
	}
	if !c.acceptQueryVariantLocked("https://example.com/other?category=Gifts", "GET") {
		t.Fatal("variant budget must be isolated per route")
	}
}

func TestEndpointLimitCapsQueuedCandidatesBeforeVisit(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.MaxEndpoints = 3
	cfg.IncludeDomains = []string{"example.com"}
	c := New("scan-cap", cfg, nil, scope.NewEngine(cfg), nil, nil)
	budget := Budget{MaxPages: 100, RequestBudget: 100}
	for i := 0; i < 50; i++ {
		c.enqueueCandidate(fmt.Sprintf("https://example.com/path/%d", i), "GET", 1, SourceLink, 0.5, "test", budget, nil, "")
	}
	if got := c.q.Len(); got != 3 {
		t.Fatalf("queued candidates=%d want 3", got)
	}
	if got := len(c.seen); got != 3 {
		t.Fatalf("seen candidates=%d want 3", got)
	}
}

func TestCrawlerTrapAvoidance(t *testing.T) {
	traps := []string{
		"https://example.com/calendar/2024/05/day",
		"https://example.com/search?filter=color&facet=size&sort=price&page=999",
		"https://example.com/list?page=1&page=2",
		"https://example.com/list?PAGE=1&page=2",
		"https://example.com/list?page%5B%5D=1&page%5B%5D=2",
		"https://example.com/list?tag=one&tag=two&tag=three&tag=four",
	}
	for _, u := range traps {
		if !IsCrawlerTrap(u) {
			t.Fatalf("expected trap: %s", u)
		}
	}
	if IsCrawlerTrap("https://example.com/api/users") {
		t.Fatal("api path should not be trap")
	}
	if IsCrawlerTrap("https://example.com/list?page=42") {
		t.Fatal("a single pagination parameter should not be a trap")
	}
	if IsCrawlerTrap("https://example.com/search?tag=go&tag=security") {
		t.Fatal("a small multi-valued non-pagination parameter should not be a trap")
	}
	for _, rawURL := range []string{
		"https://example.com/filter?category=Gifts",
		"https://example.com/products?filter=sale",
		"https://example.com/products?brand=acme&sort=price",
	} {
		if IsCrawlerTrap(rawURL) {
			t.Fatalf("ordinary faceted business URL should not be a trap: %s", rawURL)
		}
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

func TestPriorityScoringPenalizesDeepRoutes(t *testing.T) {
	shallow := ScoreEndpoint(DiscoveredEndpoint{URL: "https://example.com/products", Source: SourceLink, Confidence: 0.8, Depth: 1})
	deep := ScoreEndpoint(DiscoveredEndpoint{URL: "https://example.com/products/archive/2024/05/page/9", Source: SourceLink, Confidence: 0.8, Depth: 6})
	if shallow <= deep {
		t.Fatalf("shallow=%d deep=%d, want shallow route to be prioritized", shallow, deep)
	}
}

func TestCrawlerRetainsOrdinaryAndAPIVariantCoverage(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.MaxEndpoints = 1000
	cfg.IncludeDomains = []string{"example.com"}
	c := New("scan-query-budget", cfg, nil, scope.NewEngine(cfg), nil, nil)
	budget := Budget{MaxPages: 1000, RequestBudget: 1000}

	for i := 0; i < maxRouteQueryVariants; i++ {
		c.enqueueCandidate(fmt.Sprintf("https://example.com/filter?category=item-%d", i), "GET", 1, SourceLink, 0.9, "facet", budget, nil, "")
	}
	if got := c.q.Len(); got != maxRouteQueryVariants {
		t.Fatalf("ordinary link query variants queued=%d want %d", got, maxRouteQueryVariants)
	}

	api := New("scan-query-budget-api", cfg, nil, scope.NewEngine(cfg), nil, nil)
	for i := 0; i < maxRouteQueryVariants; i++ {
		api.enqueueCandidate(fmt.Sprintf("https://example.com/api/search?category=item-%d", i), "GET", 1, SourceBrowserXHR, 0.9, "xhr", budget, nil, "")
	}
	if got := api.q.Len(); got != maxRouteQueryVariants {
		t.Fatalf("api/runtime query variants queued=%d want %d", got, maxRouteQueryVariants)
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
	foundAsyncAPI := false
	for _, ep := range eps {
		if ep.URL == "https://example.com/asyncapi.json" {
			foundAsyncAPI = true
			break
		}
	}
	if !foundAsyncAPI {
		t.Fatal("expected AsyncAPI discovery path")
	}
}

func TestAsyncAPISpecReferenceDiscovery(t *testing.T) {
	eps := ExtractFromHTML("https://example.com/", `<script>window.spec = '/docs/asyncapi.yaml'</script>`)
	for _, ep := range eps {
		if ep.URL == "https://example.com/docs/asyncapi.yaml" && ep.Source == SourceAPIDoc {
			return
		}
	}
	t.Fatalf("expected AsyncAPI reference, got %+v", eps)
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

func TestCrawlerNeverExecutesStateChangingRequests(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"example.com"}
	c := New("scan-write-safe", cfg, nil, scope.NewEngine(cfg), nil, nil)
	budget := Budget{MaxPages: 100, RequestBudget: 100}

	// Enqueue write methods from various sources (XHR, Form, JS)
	c.enqueueCandidate("https://example.com/api/orders", "POST", 1, SourceBrowserXHR, 0.9, "xhr", budget, &RequestTemplate{
		Method: "POST", URL: "https://example.com/api/orders", Body: `{"product_id":123}`,
	}, "")
	c.enqueueCandidate("https://example.com/api/users/1", "PUT", 1, SourceBrowserXHR, 0.9, "xhr", budget, nil, "")
	c.enqueueCandidate("https://example.com/api/items/2", "DELETE", 1, SourceBrowserXHR, 0.9, "xhr", budget, nil, "")
	c.enqueueCandidate("https://example.com/api/profile", "PATCH", 1, SourceBrowserXHR, 0.9, "xhr", budget, nil, "")

	// All write requests must be recorded in seen/discovered but NEVER enqueued for execution
	if got := c.q.Len(); got != 0 {
		t.Fatalf("crawler queue must contain 0 write requests, got %d", got)
	}
	if len(c.seen) != 4 {
		t.Fatalf("all 4 endpoints should be recorded as seen, got %d", len(c.seen))
	}
}

func TestLinkedAPIDiscoveryIsNotInScopeByDefault(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"www.example.com"}
	e := scope.NewEngine(cfg)
	c := New("scan-linked-api", cfg, nil, e, nil, nil)
	budget := Budget{MaxPages: 100, RequestBudget: 100}

	// Enqueue candidates
	c.enqueueCandidate("https://www.example.com/index.html", "GET", 0, SourceSeed, 1.0, "seed", budget, nil, "")
	c.enqueueCandidate("https://api.example.com/v1/users", "GET", 1, SourceLink, 0.9, "api link", budget, nil, "https://www.example.com/index.html")
	c.enqueueCandidate("https://backend.example.com/graphql", "GET", 1, SourceLink, 0.9, "backend link", budget, nil, "https://www.example.com/index.html")
	c.enqueueCandidate("https://evil.external.com/tracking", "GET", 1, SourceLink, 0.9, "external", budget, nil, "https://www.example.com/index.html")

	c.mu.Lock()
	defer c.mu.Unlock()

	foundAPI := false
	foundBackend := false
	foundExternal := false

	for k := range c.seen {
		if strings.Contains(k, "api.example.com/v1/users") {
			foundAPI = true
		}
		if strings.Contains(k, "backend.example.com/graphql") {
			foundBackend = true
		}
		if strings.Contains(k, "evil.external.com") {
			foundExternal = true
		}
	}

	if foundAPI {
		t.Fatal("api.example.com should not be auto-admitted by default")
	}
	if foundBackend {
		t.Fatal("backend.example.com should not be auto-admitted by default")
	}
	if foundExternal {
		t.Fatal("external domain should be rejected out-of-scope")
	}
}

func TestLinkedAPIDiscoveryDuringCrawlWhenOptedIn(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"www.example.com"}
	cfg.IncludeLinkedAPISubdomains = true
	e := scope.NewEngine(cfg)
	c := New("scan-linked-api", cfg, nil, e, nil, nil)
	budget := Budget{MaxPages: 100, RequestBudget: 100}

	c.enqueueCandidate("https://www.example.com/index.html", "GET", 0, SourceSeed, 1.0, "seed", budget, nil, "")
	c.enqueueCandidate("https://api.example.com/v1/users", "GET", 1, SourceLink, 0.9, "api link", budget, nil, "https://www.example.com/index.html")
	c.enqueueCandidate("https://backend.example.com/graphql", "GET", 1, SourceLink, 0.9, "backend link", budget, nil, "https://www.example.com/index.html")

	c.mu.Lock()
	defer c.mu.Unlock()

	foundAPI := false
	foundBackend := false
	for k := range c.seen {
		if strings.Contains(k, "api.example.com/v1/users") {
			foundAPI = true
		}
		if strings.Contains(k, "backend.example.com/graphql") {
			foundBackend = true
		}
	}
	if !foundAPI {
		t.Fatal("expected api.example.com to be discovered in-scope when opted in")
	}
	if !foundBackend {
		t.Fatal("expected backend.example.com to be discovered in-scope when opted in")
	}
}

func TestSPARouteExtractionPrecisionAndGarbageRejection(t *testing.T) {
	js := `
		const icon = "/icons/user.svg";
		const theme = "/dark/theme";
		const chunk = "/static/chunks/app.chunk.js";
		const msg = "/some/random/string";
		const token = new URLSearchParams(window.location.search).get("token");

		// Syntactic route patterns
		<Route path="/admin/dashboard" />
		<NavLink to="/user/settings" />
		router.push("/orders/detail");
		navigate("/checkout/success");
		const routeObj = { path: "/reports/monthly" };
		fetch("/api/v1/profile");
	`
	eps := ExtractFromJSBundle("https://example.com/bundle.js", js)
	urlMap := make(map[string]DiscoveredEndpoint)
	for _, ep := range eps {
		urlMap[ep.URL] = ep
	}

	// Verify garbage strings are NOT extracted as routes
	garbage := []string{
		"https://example.com/icons/user.svg",
		"https://example.com/dark/theme",
		"https://example.com/some/random/string",
		"https://example.com/?token=test",
	}
	for _, g := range garbage {
		if _, exists := urlMap[g]; exists {
			t.Errorf("garbage/hallucinated endpoint should not be extracted: %s", g)
		}
	}

	// Verify valid syntactic routes are extracted with correct kind
	expectedValid := []string{
		"https://example.com/admin/dashboard",
		"https://example.com/user/settings",
		"https://example.com/orders/detail",
		"https://example.com/checkout/success",
		"https://example.com/reports/monthly",
		"https://example.com/api/v1/profile",
	}
	for _, v := range expectedValid {
		ep, exists := urlMap[v]
		if !exists {
			t.Errorf("expected syntactic route to be extracted: %s", v)
			continue
		}
		if strings.Contains(v, "/api/") && ep.Kind != KindAPI {
			t.Errorf("expected KindAPI for %s, got %s", v, ep.Kind)
		}
	}
}
