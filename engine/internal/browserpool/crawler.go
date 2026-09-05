package browserpool

import (
	"context"
	"net/http"

	"github.com/akha-security/akca/engine/internal/crawler"
)

// PageFetcher loads a URL for SPA crawl tasks executed by the worker pool.
type PageFetcher func(ctx context.Context, url string) (string, error)

// CrawlerBrowser bridges the worker pool with the crawler's BrowserFetcher hook.
type CrawlerBrowser struct {
	pool     *Pool
	do       PageFetcher
	renderer *HeadlessRenderer
}

func NewCrawlerBrowser(pool *Pool, do PageFetcher) *CrawlerBrowser {
	return NewCrawlerBrowserWithProxy(pool, do, "", false)
}

func NewCrawlerBrowserWithProxy(pool *Pool, do PageFetcher, proxyURL string, insecureTLS bool) *CrawlerBrowser {
	return NewCrawlerBrowserWithSession(pool, do, proxyURL, insecureTLS, nil, nil)
}

func NewCrawlerBrowserWithSession(pool *Pool, do PageFetcher, proxyURL string, insecureTLS bool,
	headers, cookies map[string]string) *CrawlerBrowser {
	return NewCrawlerBrowserWithSessionAndPoolSize(pool, do, proxyURL, insecureTLS, headers, cookies, 6)
}

func NewCrawlerBrowserWithSessionAndPoolSize(pool *Pool, do PageFetcher, proxyURL string, insecureTLS bool,
	headers, cookies map[string]string, poolSize int) *CrawlerBrowser {
	if pool != nil {
		pool.SetPageFetcher(do)
	}
	renderer := NewHeadlessRendererWithPoolSize(proxyURL, insecureTLS, poolSize)
	renderer.SetSession(headers, cookies)
	return &CrawlerBrowser{pool: pool, do: do, renderer: renderer}
}

func (b *CrawlerBrowser) SetConcurrency(n int) {
	if b != nil && b.renderer != nil {
		b.renderer.SetConcurrency(n)
	}
}

func (b *CrawlerBrowser) Fetch(ctx context.Context, url string) (string, []crawler.DiscoveredEndpoint, error) {
	snapshot, err := b.FetchInstrumented(ctx, url)
	return snapshot.DOM, snapshot.NetworkCalls, err
}

func (b *CrawlerBrowser) FetchInstrumented(ctx context.Context, url string) (crawler.BrowserSnapshot, error) {
	if b.pool != nil {
		b.pool.Enqueue(Task{Type: TaskSPACrawl, URL: url})
	}
	var body string
	var err error
	if b.renderer != nil && b.renderer.Available() {
		snapshot, captureErr := b.renderer.Capture(ctx, url)
		if captureErr == nil {
			return snapshot, nil
		}
		body, err = b.renderer.Render(ctx, url)
		if err != nil && b.do != nil {
			// A locally installed browser can still fail at runtime because of
			// sandbox, profile, policy, or startup issues. Preserve crawl
			// coverage with the authenticated HTTP bridge.
			body, err = b.do(ctx, url)
		}
	} else if b.do != nil {
		body, err = b.do(ctx, url)
	}
	if err != nil {
		return crawler.BrowserSnapshot{}, err
	}
	if body == "" {
		return crawler.BrowserSnapshot{URL: url}, nil
	}
	xhr := crawler.ExtractFromHTML(url, body)
	xhr = append(xhr, crawler.ExtractFromJSBundle(url, body)...)
	xhr = append(xhr, crawler.ExtractASTFromJSBundle(url, body)...)
	for i := range xhr {
		if xhr[i].Source != crawler.SourceForm {
			xhr[i].Source = crawler.SourceBrowserXHR
		}
		xhr[i].WhyDiscovered = "rendered browser DOM/XHR extraction"
	}
	return crawler.BuildBrowserSnapshot(url, body, xhr), nil
}

// HTTPPageFetcher adapts a generic HTTP doer into a page fetcher.
func HTTPPageFetcher(do func(ctx context.Context, method, url string, body []byte, headers map[string]string) (string, error)) PageFetcher {
	return func(ctx context.Context, url string) (string, error) {
		return do(ctx, http.MethodGet, url, nil, nil)
	}
}
