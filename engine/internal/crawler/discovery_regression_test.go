package crawler

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

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

type pausingBrowser struct {
	entered chan struct{}
	release chan struct{}
}

func (b *pausingBrowser) Fetch(context.Context, string) (string, []DiscoveredEndpoint, error) {
	return "", nil, nil
}

func (b *pausingBrowser) FetchInstrumented(ctx context.Context, rawURL string) (BrowserSnapshot, error) {
	select {
	case b.entered <- struct{}{}:
	default:
	}
	select {
	case <-b.release:
		return BrowserSnapshot{URL: rawURL, DocumentStatus: 200, DOM: "<html>rendered</html>"}, nil
	case <-ctx.Done():
		return BrowserSnapshot{}, ctx.Err()
	}
}

type seedErrorClient struct {
	*discoveryClient
	err error
}

type cooldownObservationClient struct {
	*discoveryClient
	cooldown time.Duration
	deadline time.Duration
}

func (c *cooldownObservationClient) HostCooldownRemaining(string) time.Duration { return c.cooldown }

func (c *cooldownObservationClient) Do(ctx context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	if rawURL == "https://example.test/" {
		if deadline, ok := ctx.Deadline(); ok {
			c.deadline = time.Until(deadline)
		}
	}
	return c.discoveryClient.Do(ctx, method, rawURL, body, headers)
}

func (c *seedErrorClient) Do(ctx context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	if rawURL == "https://example.test/" {
		return httpclient.RequestResponse{}, c.err
	}
	return c.discoveryClient.Do(ctx, method, rawURL, body, headers)
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

func TestStaticAssetDirectoriesAreInferred(t *testing.T) {
	got := staticAssetDirectoryURLs("https://example.test/assets/icons/logo.png?v=4#preview", 4)
	want := []string{"https://example.test/assets/icons/", "https://example.test/assets/"}
	if len(got) != len(want) {
		t.Fatalf("inferred directories = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("inferred directory %d = %q, want %q", i, got[i], want[i])
		}
	}
	if got := staticAssetDirectoryURLs("https://example.test/logo.png", 4); len(got) != 0 {
		t.Fatalf("origin root must not be redundantly inferred: %#v", got)
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

func TestBlockedEntryStillDiscoversSitemapPages(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"example.test"}
	db, err := storage.Open(t.TempDir() + "/sitemap-recovery.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	client := &discoveryClient{responses: map[string]httpclient.ResponseRecord{
		"https://example.test/":            {StatusCode: 403},
		"https://example.test/sitemap.xml": {StatusCode: 200, Headers: map[string]string{"Content-Type": "application/xml"}, Body: `<urlset><url><loc>https://example.test/public</loc></url></urlset>`},
		"https://example.test/public":      {StatusCode: 200, Headers: map[string]string{"Content-Type": "text/html"}, Body: `<html><a href="/child">child</a></html>`},
		"https://example.test/child":       {StatusCode: 200, Headers: map[string]string{"Content-Type": "text/html"}, Body: `<html>child</html>`},
	}, visited: map[string]bool{}}
	c := New("sitemap-recovery", cfg, client, scope.NewEngine(cfg), db, nil)
	c.SetBrowser(&documentBrowser{status: 0})
	if err := c.Crawl(context.Background(), []string{"https://example.test/"}); err != nil {
		t.Fatal(err)
	}
	if !client.visited["https://example.test/public"] || !client.visited["https://example.test/child"] {
		t.Fatalf("sitemap pages were not crawled: %v", client.visited)
	}
}

func TestStaticLinksPersistBeforeBrowserNavigationFinishes(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"example.test"}
	db, err := storage.Open(t.TempDir() + "/early-links.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	client := &discoveryClient{responses: map[string]httpclient.ResponseRecord{
		"https://example.test/":      {StatusCode: 200, Headers: map[string]string{"Content-Type": "text/html"}, Body: `<html><script src="/app.js"></script><a href="/child">child</a></html>`},
		"https://example.test/child": {StatusCode: 200, Headers: map[string]string{"Content-Type": "text/html"}, Body: "<html>child</html>"},
	}, visited: map[string]bool{}}
	browser := &pausingBrowser{entered: make(chan struct{}, 1), release: make(chan struct{}, 1)}
	c := New("early-links", cfg, client, scope.NewEngine(cfg), db, nil)
	c.SetBrowser(browser)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- c.Crawl(ctx, []string{"https://example.test/"}) }()
	select {
	case <-browser.entered:
	case <-ctx.Done():
		t.Fatal("browser navigation did not start")
	}
	if _, err := db.GetEndpointID("early-links", "https://example.test/child", "GET"); err != nil {
		t.Fatalf("observed link was not saved before browser navigation finished: %v", err)
	}
	browser.release <- struct{}{}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}

func TestCrawlVisitsHTMLPagesBeforeScriptChunks(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"example.test"}
	cfg.EnableHeadlessCrawler = false
	cfg.MaxPages = 5
	cfg.CrawlerRequestBudget = 5
	db, err := storage.Open(t.TempDir() + "/page-priority.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	var html strings.Builder
	html.WriteString("<html>")
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&html, `<script src="/_next/static/chunks/%d.js"></script>`, i)
	}
	for _, path := range []string{"uyelik", "iletisim", "kullanim-kosullari", "sifre-yenileme"} {
		fmt.Fprintf(&html, `<a href="/%s">page</a>`, path)
	}
	html.WriteString("</html>")
	client := &discoveryClient{responses: map[string]httpclient.ResponseRecord{
		"https://example.test/": {StatusCode: 200, Headers: map[string]string{"Content-Type": "text/html"}, Body: html.String()},
	}, visited: map[string]bool{}}
	c := New("page-priority", cfg, client, scope.NewEngine(cfg), db, nil)
	_ = c.Crawl(context.Background(), []string{"https://example.test/"})
	for _, path := range []string{"uyelik", "iletisim", "kullanim-kosullari", "sifre-yenileme"} {
		if !client.visited["https://example.test/"+path] {
			t.Fatalf("HTML page /%s lost to script chunks: %v", path, client.visited)
		}
	}
	for url := range client.visited {
		if strings.Contains(url, "/_next/static/chunks/") {
			t.Fatalf("script chunk consumed limited crawl budget before pages: %s", url)
		}
	}
}

func TestCrawlerDeadlineIncludesHostCooldown(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"example.test"}
	cfg.MaxPages = 1
	cfg.CrawlerRequestBudget = 1
	db, err := storage.Open(t.TempDir() + "/cooldown.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	client := &cooldownObservationClient{discoveryClient: &discoveryClient{
		responses: map[string]httpclient.ResponseRecord{
			"https://example.test/": {StatusCode: 200, Headers: map[string]string{"Content-Type": "text/html"}, Body: "<html>ok</html>"},
		}, visited: map[string]bool{},
	}, cooldown: 30 * time.Second}
	c := New("cooldown", cfg, client, scope.NewEngine(cfg), db, nil)
	if err := c.Crawl(context.Background(), []string{"https://example.test/"}); err != nil {
		t.Fatal(err)
	}
	if client.deadline < 45*time.Second {
		t.Fatalf("crawler deadline ignored host cooldown: %s", client.deadline)
	}
}

func TestSeedTransportErrorBrowserRecovery(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"example.test"}
	db, err := storage.Open(t.TempDir() + "/transport-browser.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	client := &seedErrorClient{discoveryClient: &discoveryClient{
		responses: map[string]httpclient.ResponseRecord{
			"https://example.test/browser-child": {StatusCode: 200, Body: "ok"},
		}, visited: map[string]bool{},
	}, err: context.DeadlineExceeded}
	c := New("transport-browser", cfg, client, scope.NewEngine(cfg), db, nil)
	c.SetBrowser(&documentBrowser{status: 200})
	if err := c.Crawl(context.Background(), []string{"https://example.test/"}); err != nil {
		t.Fatal(err)
	}
	if c.browserAttemptCount() != 1 || c.browserRecoveryCount() != 1 || !client.visited["https://example.test/browser-child"] {
		t.Fatalf("browser recovery did not discover child: attempts=%d recovered=%d visited=%v", c.browserAttemptCount(), c.browserRecoveryCount(), client.visited)
	}
}

func TestSeedHostPressureDoesNotLaunchBrowser(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"example.test"}
	db, err := storage.Open(t.TempDir() + "/pressure-browser.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	client := &seedErrorClient{discoveryClient: &discoveryClient{responses: map[string]httpclient.ResponseRecord{}, visited: map[string]bool{}}, err: httpclient.ErrHostDeferred}
	c := New("pressure-browser", cfg, client, scope.NewEngine(cfg), db, nil)
	c.SetBrowser(&documentBrowser{status: 200})
	if err := c.Crawl(context.Background(), []string{"https://example.test/"}); err == nil {
		t.Fatalf("host pressure should leave crawl incomplete: %v", err)
	}
	if c.browserAttemptCount() != 0 {
		t.Fatalf("browser launched under host pressure: %d", c.browserAttemptCount())
	}
}

func TestBrowserRecoveryCoversAuthAndChallengeStatuses(t *testing.T) {
	for _, responseStatus := range []int{401, 403, 429, 503, 556} {
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

func TestCrawlerRejectsFailedPagesBeforeScannerSelection(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"example.test"}
	db, err := storage.Open(t.TempDir() + "/failed-pages.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	client := &discoveryClient{responses: map[string]httpclient.ResponseRecord{
		"https://example.test/":        {StatusCode: 200, Headers: map[string]string{"Content-Type": "text/html"}, Body: `<a href="/missing">missing</a>`},
		"https://example.test/missing": {StatusCode: 404, Headers: map[string]string{"Content-Type": "text/html"}, Body: `<a href="/ghost">ghost</a>`},
	}, visited: map[string]bool{}}
	c := New("failed-pages", cfg, client, scope.NewEngine(cfg), db, nil)
	if err := c.Crawl(context.Background(), []string{"https://example.test/"}); err != nil {
		t.Fatal(err)
	}
	if !client.visited["https://example.test/missing"] {
		t.Fatal("expected the linked 404 to be checked")
	}
	if client.visited["https://example.test/ghost"] {
		t.Fatal("404 response body was used for link discovery")
	}
	var count int
	if err := db.Conn().QueryRow(`SELECT COUNT(*) FROM endpoints WHERE scan_id = ? AND url = ?`, "failed-pages", "https://example.test/missing").Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed link remained in scanner inventory: count=%d err=%v", count, err)
	}
	endpoints, err := db.ListDiscoveryEndpoints("failed-pages", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, ep := range endpoints {
		if ep.URL == "https://example.test/missing" || ep.URL == "https://example.test/ghost" {
			t.Fatalf("failed page reached active target selection: %+v", ep)
		}
	}
}

func TestFailedSeedStatusIsStoredButExcludedFromActiveTargets(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"example.test"}
	db, err := storage.Open(t.TempDir() + "/failed-seed.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	client := &discoveryClient{responses: map[string]httpclient.ResponseRecord{
		"https://example.test/": {StatusCode: 404, Body: `<a href="/ghost">ghost</a>`},
	}, visited: map[string]bool{}}
	c := New("failed-seed", cfg, client, scope.NewEngine(cfg), db, nil)
	_ = c.Crawl(context.Background(), []string{"https://example.test/"})
	var status int
	if err := db.Conn().QueryRow(`SELECT COALESCE(json_extract(discovery_trail_json, '$.request_template.response_status'), 0) FROM endpoints WHERE scan_id = ? AND url = ?`, "failed-seed", "https://example.test/").Scan(&status); err != nil || status != 404 {
		t.Fatalf("seed failure status was not saved: status=%d err=%v", status, err)
	}
	endpoints, err := db.ListDiscoveryEndpoints("failed-seed", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, ep := range endpoints {
		if ep.URL == "https://example.test/" {
			t.Fatal("failed seed reached active target selection")
		}
	}
	if client.visited["https://example.test/ghost"] {
		t.Fatal("failed seed body was used for link discovery")
	}
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
