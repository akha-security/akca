package crawler

import (
	"strings"
	"testing"
)

func astURLs(eps []DiscoveredEndpoint) map[string]string {
	out := map[string]string{}
	for _, ep := range eps {
		out[ep.URL] = ep.Method
	}
	return out
}

func TestASTExtractionCallSites(t *testing.T) {
	js := `
		fetch(
			"/api/v1/users"
		);
		axios.post("/api/v1/orders", {});
		axios({ url: "/api/v1/config", method: "PUT" });
		const xhr = new XMLHttpRequest();
		xhr.open("DELETE", "/api/v1/items/42");
		const ws = new WebSocket("wss://example.com/live");
		new EventSource("/api/v1/stream");
		import("/chunks/lazy.js");
		$.ajax({ url: "/api/v1/jq", method: "POST" });
	`
	eps := ExtractASTFromJSBundle("https://example.com/app.js", js)
	got := astURLs(eps)

	checks := []struct {
		urlSuffix string
		method    string
	}{
		{"/api/v1/users", "GET"},
		{"/api/v1/orders", "POST"},
		{"/api/v1/config", "PUT"},
		{"/api/v1/items/42", "DELETE"},
		{"/live", "GET"},
		{"/api/v1/stream", "GET"},
		{"/chunks/lazy.js", "GET"},
		{"/api/v1/jq", "POST"},
	}
	for _, c := range checks {
		found := false
		for u, m := range got {
			if strings.HasSuffix(u, c.urlSuffix) && m == c.method {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %s %s in AST extraction, got %v", c.method, c.urlSuffix, got)
		}
	}
}

func TestASTTemplateLiteralPrefix(t *testing.T) {
	js := "fetch(`/api/v1/users/${id}/profile`);"
	eps := ExtractASTFromJSBundle("https://example.com/app.js", js)
	if len(eps) == 0 {
		t.Fatal("expected template-literal endpoint to be extracted")
	}
	if !strings.Contains(eps[0].URL, "/api/v1/users/") {
		t.Fatalf("expected static prefix from template literal, got %s", eps[0].URL)
	}
}

func TestASTIgnoresComments(t *testing.T) {
	js := `
		// fetch("/api/should-be-ignored");
		/* axios.get("/api/also-ignored"); */
		fetch("/api/real");
	`
	eps := ExtractASTFromJSBundle("https://example.com/app.js", js)
	for _, ep := range eps {
		if strings.Contains(ep.URL, "ignored") {
			t.Fatalf("commented-out call should be ignored, got %s", ep.URL)
		}
	}
	if len(eps) != 1 {
		t.Fatalf("expected exactly 1 real endpoint, got %v", eps)
	}
}
