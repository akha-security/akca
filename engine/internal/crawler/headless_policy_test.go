package crawler

import (
	"net/http"
	"testing"
)

func TestShouldRenderWithBrowserPrioritizesRuntimeDocuments(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		source DiscoverySource
		status int
		want   bool
	}{
		{"scripted seed", `<html><script src="/app.js"></script></html>`, SourceSeed, 200, true},
		{"linked spa shell", `<div id="root"></div><script src="/app.js"></script>`, SourceLink, 200, true},
		{"linked module app", `<script type="module" src="/app.js"></script>`, SourceLink, 200, true},
		{"ordinary multipage document", `<a href="/next">next</a><script src="/analytics.js"></script>`, SourceLink, 200, false},
		{"no script", `<a href="/next">next</a>`, SourceLink, 200, false},
		{"rejected document", `<script src="/app.js"></script>`, SourceSeed, 403, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldRenderWithBrowser(tt.body, tt.source, http.MethodGet, tt.status); got != tt.want {
				t.Fatalf("shouldRenderWithBrowser()=%v, want %v", got, tt.want)
			}
		})
	}
}

func TestShouldRenderWithBrowserRejectsNonGET(t *testing.T) {
	if shouldRenderWithBrowser(`<div id="root"></div><script src="/app.js"></script>`, SourceLink, http.MethodPost, 200) {
		t.Fatal("POST response must not trigger a browser navigation")
	}
}
