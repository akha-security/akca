package crawler

import (
	"context"
	"net/http"
)

// BrowserFetcher is a headless-browser hook for SPA crawling and XHR capture.
type BrowserFetcher interface {
	Fetch(ctx context.Context, url string) (html string, xhrCalls []DiscoveredEndpoint, err error)
}

type BrowserSnapshot struct {
	URL            string                `json:"url"`
	DOM            string                `json:"dom"`
	NetworkEvents  []BrowserNetworkEvent `json:"network_events,omitempty"`
	NetworkCalls   []DiscoveredEndpoint  `json:"network_calls,omitempty"`
	WebSockets     []string              `json:"websockets,omitempty"`
	ServiceWorkers []string              `json:"service_workers,omitempty"`
	Cookies        map[string]string     `json:"cookies,omitempty"`
	SessionStorage map[string]string     `json:"session_storage,omitempty"`
	LocalStorage   map[string]string     `json:"local_storage,omitempty"`
	VisibleActions []string              `json:"visible_actions,omitempty"`
	Forms          []string              `json:"forms,omitempty"`
	DOMSinkEvents  []string              `json:"dom_sink_events,omitempty"`
}

type BrowserNetworkEvent struct {
	RequestID       string            `json:"request_id"`
	URL             string            `json:"url"`
	Method          string            `json:"method"`
	ResourceType    string            `json:"resource_type"`
	StatusCode      int               `json:"status_code,omitempty"`
	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	RequestBody     string            `json:"request_body,omitempty"`
	ResponseBody    string            `json:"response_body,omitempty"`
}

type InstrumentedBrowserFetcher interface {
	BrowserFetcher
	FetchInstrumented(ctx context.Context, url string) (BrowserSnapshot, error)
}

// HTTPBrowserStub is retained only as a deterministic unit-test fallback.
// Production crawling is wired through browserpool.CrawlerBrowser, which uses
// Chromium instrumentation when available and an authenticated HTTP fallback
// otherwise.
type HTTPBrowserStub struct {
	Do func(ctx context.Context, method, url string, body []byte, headers map[string]string) (string, error)
}

func (b *HTTPBrowserStub) Fetch(ctx context.Context, url string) (string, []DiscoveredEndpoint, error) {
	if b.Do == nil {
		return "", nil, nil
	}
	body, err := b.Do(ctx, http.MethodGet, url, nil, nil)
	if err != nil {
		return "", nil, err
	}
	xhr := ExtractFromJSBundle(url, body)
	for i := range xhr {
		xhr[i].Source = SourceBrowserXHR
		xhr[i].WhyDiscovered = "browser stub xhr/api extraction"
	}
	return body, xhr, nil
}

func (b *HTTPBrowserStub) FetchInstrumented(ctx context.Context, rawURL string) (BrowserSnapshot, error) {
	html, calls, err := b.Fetch(ctx, rawURL)
	if err != nil {
		return BrowserSnapshot{}, err
	}
	return BuildBrowserSnapshot(rawURL, html, calls), nil
}
