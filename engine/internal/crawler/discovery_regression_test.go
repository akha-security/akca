package crawler

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
)

type discoveryClient struct {
	mu             sync.Mutex
	responses      map[string]httpclient.ResponseRecord
	visited        map[string]bool
	sessionCookies map[string]string
}

type documentBrowser struct {
	HTTPBrowserStub
	status int
}

func (b *documentBrowser) FetchInstrumented(_ context.Context, rawURL string) (BrowserSnapshot, error) {
	return BrowserSnapshot{URL: rawURL, DocumentStatus: b.status, DOM: `<a href="/browser-child">child</a>`}, nil
}

func TestBrowserBlockedResourcesAreSummarizedOnce(t *testing.T) {
	var events int
	var message string
	var payload map[string]interface{}
	c := &Crawler{
		browserBlocked: make(map[string]struct{}),
		emit: func(kind, eventMessage string, eventPayload map[string]interface{}) error {
			if kind == "coverage_gap" {
				events++
				message = eventMessage
				payload = eventPayload
			}
			return nil
		},
	}
	c.recordBrowserBlocked([]string{
		"https://cdn.example.test/app.js?token=secret",
		"https://cdn.example.test/app.js?token=secret",
		"https://fonts.example.test/font.woff2",
	})
	c.recordBrowserBlocked([]string{"https://cdn.example.test/theme.css"})
	c.emitBrowserBlockedSummary()

	if events != 1 {
		t.Fatalf("browser policy gap should be emitted once, got %d", events)
	}
	if strings.Contains(message, "token=secret") {
		t.Fatalf("blocked URL leaked into event message: %s", message)
	}
	if got := payload["blocked_requests"]; got != 3 {
		t.Fatalf("blocked request count = %v, want 3", got)
	}
	hosts, ok := payload["blocked_hosts"].([]string)
	if !ok || len(hosts) != 2 || hosts[0] != "cdn.example.test" || hosts[1] != "fonts.example.test" {
		t.Fatalf("blocked hosts = %#v", payload["blocked_hosts"])
	}
}

func TestDeniedDocumentBrowserRecovery(t *testing.T) {
	for _, status := range []int{200, 403, 0} {
		cfg := config.DefaultScanConfig()
		cfg.IncludeDomains = []string{"example.test"}
		db, err := storage.Open(t.TempDir() + "/browser.db")
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Migrate(); err != nil {
			t.Fatal(err)
		}
		client := &discoveryClient{responses: map[string]httpclient.ResponseRecord{
			"https://example.test/": {StatusCode: 403},
		}, visited: map[string]bool{}}
		c := New("browser-recovery", cfg, client, scope.NewEngine(cfg), db, func(string, string, map[string]interface{}) error { return nil })
		c.SetBrowser(&documentBrowser{status: status})
		err = c.Crawl(context.Background(), []string{"https://example.test/"})
		if status == 200 {
			if err != nil || !client.visited["https://example.test/browser-child"] {
				t.Fatalf("browser recovery failed: %v", err)
			}
		} else if err == nil || client.visited["https://example.test/browser-child"] {
			t.Fatalf("rejected/unverified browser document accepted: status=%d err=%v", status, err)
		}
		db.Close()
	}
}

func TestBrowserRecoveryCoversAuthAndChallengeStatuses(t *testing.T) {
	for _, responseStatus := range []int{401, 403, 429, 503} {
		t.Run(http.StatusText(responseStatus), func(t *testing.T) {
			cfg := config.DefaultScanConfig()
			cfg.IncludeDomains = []string{"example.test"}
			db, err := storage.Open(t.TempDir() + "/browser-challenge.db")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if err = db.Migrate(); err != nil {
				t.Fatal(err)
			}
			client := &discoveryClient{responses: map[string]httpclient.ResponseRecord{
				"https://example.test/":              {StatusCode: responseStatus},
				"https://example.test/browser-child": {StatusCode: 200, Body: "ok"},
			}, visited: map[string]bool{}}
			c := New("browser-challenge", cfg, client, scope.NewEngine(cfg), db, nil)
			c.SetBrowser(&documentBrowser{status: 200})
			if err = c.Crawl(context.Background(), []string{"https://example.test/"}); err != nil {
				t.Fatalf("HTTP %d was not recovered through browser: %v", responseStatus, err)
			}
			if !client.visited["https://example.test/browser-child"] {
				t.Fatalf("HTTP %d browser DOM was not crawled", responseStatus)
			}
		})
	}
}

func TestBrowserCookiesAreAdoptedForLaterCrawlRequests(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"example.test"}
	db, err := storage.Open(t.TempDir() + "/browser-session.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Migrate(); err != nil {
		t.Fatal(err)
	}
	client := &discoveryClient{responses: map[string]httpclient.ResponseRecord{
		"https://example.test/":              {StatusCode: 403},
		"https://example.test/browser-child": {StatusCode: 200, Body: "ok"},
	}, visited: map[string]bool{}}
	c := New("browser-session", cfg, client, scope.NewEngine(cfg), db, nil)
	c.SetBrowser(&cookieDocumentBrowser{})
	if err = c.Crawl(context.Background(), []string{"https://example.test/"}); err != nil {
		t.Fatal(err)
	}
	if client.sessionCookies["clearance"] != "browser-value" {
		t.Fatalf("browser cookies were not adopted: %v", client.sessionCookies)
	}
	if _, invalid := client.sessionCookies[".example.test|sid"]; invalid {
		t.Fatalf("ambiguous CDP cookie name was adopted: %v", client.sessionCookies)
	}
}

type cookieDocumentBrowser struct{ documentBrowser }

func (b *cookieDocumentBrowser) FetchInstrumented(_ context.Context, rawURL string) (BrowserSnapshot, error) {
	return BrowserSnapshot{
		URL: rawURL, DocumentStatus: 200, DOM: `<a href="/browser-child">child</a>`,
		Cookies: map[string]string{"clearance": "browser-value", ".example.test|sid": "ambiguous"},
	}, nil
}

func (c *discoveryClient) SetSession(cookies map[string]string, _ map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessionCookies = make(map[string]string, len(cookies))
	for key, value := range cookies {
		c.sessionCookies[key] = value
	}
}

func TestCrawlerRejectsEmptyForbiddenScan(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"example.test"}
	db, err := storage.Open(t.TempDir() + "/blocked.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	client := &discoveryClient{responses: map[string]httpclient.ResponseRecord{
		"https://example.test/": {StatusCode: 403, Headers: map[string]string{"proxy-reason": "blocked malicious bot"}},
	}, visited: map[string]bool{}}
	var mu sync.Mutex
	warned := false
	c := New("blocked", cfg, client, scope.NewEngine(cfg), db, func(kind, message string, payload map[string]interface{}) error {
		mu.Lock()
		defer mu.Unlock()
		if kind == "coverage_gap" && strings.Contains(message, "HTTP 403") {
			warned = true
		}
		return nil
	})
	err = c.Crawl(context.Background(), []string{"https://example.test/"})
	if err == nil || !strings.Contains(err.Error(), "no usable page content") {
		t.Fatalf("empty blocked crawl must fail, got %v", err)
	}
	if !warned {
		t.Fatal("missing blocked seed coverage warning")
	}
}

func (c *discoveryClient) Do(_ context.Context, method, rawURL string, _ []byte, _ map[string]string) (httpclient.RequestResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.visited[rawURL] = true
	response, ok := c.responses[rawURL]
	if !ok {
		response = httpclient.ResponseRecord{StatusCode: 404}
	}
	return httpclient.RequestResponse{Request: httpclient.RequestRecord{URL: rawURL, Method: method}, Response: response}, nil
}

func TestCrawlFollowsRedirectAndRenderedLinks(t *testing.T) {
	for _, tc := range []struct {
		name      string
		seed      httpclient.ResponseRecord
		responses map[string]httpclient.ResponseRecord
		browser   bool
		want      string
		absent    string
	}{
		{name: "canonical host redirect", seed: httpclient.ResponseRecord{StatusCode: 301, Headers: map[string]string{"location": "https://www.example.test/app/"}},
			responses: map[string]httpclient.ResponseRecord{"https://www.example.test/app/": {StatusCode: 200, Body: `<a href="child">child</a>`}}, want: "https://www.example.test/app/child"},
		{name: "final document base", seed: httpclient.ResponseRecord{StatusCode: 200, FinalURL: "https://example.test/app/", Body: `<a href="child">child</a>`}, want: "https://example.test/app/child", absent: "https://example.test/child"},
		{name: "rendered DOM", seed: httpclient.ResponseRecord{StatusCode: 200, Body: `<html><script src="/app.js"></script></html>`}, browser: true, want: "https://example.test/rendered"},
		{name: "external redirect stays excluded", seed: httpclient.ResponseRecord{StatusCode: 302, Headers: map[string]string{"Location": "https://external.test/"}}, absent: "https://external.test/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DefaultScanConfig()
			cfg.IncludeDomains = []string{"example.test"}
			db, err := storage.Open(t.TempDir() + "/crawl.db")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if err := db.Migrate(); err != nil {
				t.Fatal(err)
			}
			client := &discoveryClient{responses: map[string]httpclient.ResponseRecord{"https://example.test/": tc.seed}, visited: map[string]bool{}}
			for key, value := range tc.responses {
				client.responses[key] = value
			}
			c := New("discovery", cfg, client, scope.NewEngine(cfg), db, func(string, string, map[string]interface{}) error { return nil })
			if tc.browser {
				c.SetBrowser(&HTTPBrowserStub{Do: func(context.Context, string, string, []byte, map[string]string) (string, error) {
					return `<a href="/rendered">rendered only</a>`, nil
				}})
			}
			if err := c.Crawl(context.Background(), []string{"https://example.test/"}); err != nil && tc.want != "" {
				t.Fatal(err)
			}
			if tc.want != "" && !client.visited[tc.want] {
				t.Fatalf("missing crawl request: %s", tc.want)
			}
			if tc.absent != "" && client.visited[tc.absent] {
				t.Fatalf("unexpected crawl request: %s", tc.absent)
			}
		})
	}
}
