package browserpool

import (
	"context"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/crawler"
)

func TestCrawlerBrowserUsesHTTPFallbackAndBuildsInstrumentedSnapshot(t *testing.T) {
	var calls int
	browser := &CrawlerBrowser{
		renderer: &HeadlessRenderer{},
		do: func(_ context.Context, rawURL string) (string, error) {
			calls++
			return `<script>fetch("/api/private"); new WebSocket("wss://example.test/socket")</script>`, nil
		},
	}
	snapshot, err := browser.FetchInstrumented(context.Background(), "https://example.test/app")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("HTTP fallback calls = %d, want 1", calls)
	}
	if snapshot.DOM == "" || len(snapshot.NetworkCalls) == 0 {
		t.Fatalf("expected instrumented fallback snapshot, got %#v", snapshot)
	}
	foundAPI := false
	for _, endpoint := range snapshot.NetworkCalls {
		if strings.Contains(endpoint.URL, "/api/private") {
			foundAPI = true
			if endpoint.Source != crawler.SourceBrowserXHR {
				t.Fatalf("endpoint source = %q, want %q", endpoint.Source, crawler.SourceBrowserXHR)
			}
		}
	}
	if !foundAPI {
		t.Fatalf("fallback snapshot did not discover API endpoint: %#v", snapshot.NetworkCalls)
	}
}
