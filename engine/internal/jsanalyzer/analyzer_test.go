package jsanalyzer

import (
	"strings"
	"testing"
)

func TestASTAndHeuristicExtraction(t *testing.T) {
	js := `
fetch("/api/v1/users");
axios.post("/graphql");
const x = "/internal/only-ast";
`
	ast := ExtractASTLite(js)
	heur := ExtractHeuristic(js)
	if len(ast) == 0 {
		t.Fatal("expected ast extraction")
	}
	if len(heur) == 0 {
		t.Fatal("expected heuristic extraction")
	}
}

func TestMinifiedFallbackExtraction(t *testing.T) {
	minified := `!function(){fetch("/api/x");new WebSocket("wss://example.com/live")}();`
	eps := ExtractHeuristic(minified)
	if len(eps) < 2 {
		t.Fatalf("expected minified endpoints, got %d", len(eps))
	}
}

func TestRouteManifestExtraction(t *testing.T) {
	js := `__NEXT_DATA__ = {"props":{},"pathname":"/dashboard"}; window.__NUXT__={};`
	eps := ExtractHeuristic(js)
	found := false
	for _, ep := range eps {
		if strings.Contains(ep.URL, "dashboard") || strings.Contains(ep.Source, "nuxt") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected manifest routes, got %v", eps)
	}
}

func TestSecretRedaction(t *testing.T) {
	js := `const key = "AKIAIOSFODNN7EXAMP1A"; const token = "ghp_1234567890abcdefghijklmnop";`
	secrets := DetectSecrets(js)
	if len(secrets) < 2 {
		t.Fatalf("expected secrets, got %d", len(secrets))
	}
	for _, s := range secrets {
		if strings.Contains(s.Redacted, "AKIAIOSFODNN7EXAMP1A") {
			t.Fatal("secret not redacted")
		}
	}
}

func TestExpandedSecretDetection(t *testing.T) {
	stripeFixture := "sk_" + "live_0123456789abcdefghij0123"
	js := `
const google = "AIza012345678901234567890123456789abcde";
const stripe = "` + stripeFixture + `";
const slack = "https://hooks.slack.com/services/T00000000/B00000000/abcdefABCDEF1234";
const dbURL = "https://admin:secretPass123@db.internal.example.com";
const openai = "sk-proj-abcdefghijklmnopqrstuvwxyz0123";
const placeholder = { api_key: "your_api_key_here_value" };
`
	secrets := DetectSecrets(js)
	got := map[string]bool{}
	for _, s := range secrets {
		got[s.Kind] = true
		if strings.Contains(s.Redacted, "secretPass123") {
			t.Fatalf("credential not redacted: %s", s.Redacted)
		}
	}
	for _, want := range []string{"google_api_key", "stripe_secret_key", "slack_webhook", "basic_auth_url", "openai_key"} {
		if !got[want] {
			t.Fatalf("expected secret kind %q, got %v", want, got)
		}
	}
	if got["api_key"] {
		t.Fatal("placeholder api_key should have been filtered out")
	}
}

func TestConfigURLAndInternalPathExtraction(t *testing.T) {
	js := `
const cfg = { baseURL: "https://api.internal.example.com/v2", apiUrl: "/api/v3" };
import("./secret-internal-module.js");
`
	heur := ExtractHeuristic(js)
	foundConfig := false
	for _, ep := range heur {
		if ep.Source == "config" {
			foundConfig = true
		}
	}
	if !foundConfig {
		t.Fatalf("expected config-style API URL endpoint, got %v", heur)
	}
	paths := DetectInternalPaths(js)
	if len(paths) == 0 || paths[0].Kind != "internal" {
		t.Fatalf("expected internal path detection, got %v", paths)
	}
}

func TestConfidenceFiltering(t *testing.T) {
	eps := []ExtractedEndpoint{
		{URL: "/api/users", Method: "GET", Confidence: 0.9},
		{URL: "x", Method: "GET", Confidence: 0.2},
	}
	filtered := FilterByConfidence(eps, MinConfidence)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 endpoint after filter, got %d", len(filtered))
	}
}

func TestSemanticDeduplication(t *testing.T) {
	eps := []ExtractedEndpoint{
		{URL: "/users/123", Method: "GET", Confidence: 0.7},
		{URL: "/users/456", Method: "GET", Confidence: 0.8},
	}
	deduped := DeduplicateSemantic(eps)
	if len(deduped) != 1 {
		t.Fatalf("expected semantic dedupe to 1, got %d", len(deduped))
	}
	if deduped[0].Confidence != 0.8 {
		t.Fatalf("expected highest confidence kept, got %v", deduped[0].Confidence)
	}
}

func TestLargeFilePreviewHandling(t *testing.T) {
	huge := strings.Repeat("a", DefaultMaxJSBytes+1000) + `fetch("/api/huge");`
	content, truncated, previewOnly := PrepareContent(huge, DefaultMaxJSBytes, DefaultPreviewBytes)
	if !truncated || !previewOnly {
		t.Fatalf("expected truncated preview, truncated=%v previewOnly=%v", truncated, previewOnly)
	}
	if len(content) != DefaultPreviewBytes {
		t.Fatalf("expected preview bytes %d, got %d", DefaultPreviewBytes, len(content))
	}
}

func TestSourceMapDetection(t *testing.T) {
	js := `//# sourceMappingURL=app.js.map`
	maps := DetectSourceMaps("https://example.com/app.js", js)
	if len(maps) != 1 || maps[0].URL != "app.js.map" {
		t.Fatalf("unexpected source maps: %v", maps)
	}
}
