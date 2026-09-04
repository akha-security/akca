package app

import (
	"context"

	"github.com/akha-security/akca/engine/internal/browserpool"
	"github.com/akha-security/akca/engine/internal/crawler"
)

// runJSDiscoveredCrawlPhase crawls API/endpoint URLs extracted from JavaScript
// bundles so authenticated and linked APIs enter the endpoint graph.
func (e *Engine) runJSDiscoveredCrawlPhase(ctx context.Context) error {
	limit := e.session.Config.EffectiveMaxPages()
	jsEps, err := e.db.ListJSDiscoveredAPIEndpoints(e.session.ID, limit)
	if err != nil || len(jsEps) == 0 {
		return err
	}
	seeds := make([]crawler.DiscoveredEndpoint, 0, len(jsEps))
	for _, ep := range jsEps {
		de := crawler.DiscoveredEndpoint{
			URL: ep.URL, Method: ep.Method, Source: crawler.SourceJSBundle,
			Confidence: 0.8, WhyDiscovered: "js api re-crawl",
		}
		if ep.Body != "" || ep.ContentType != "" || len(ep.Headers) > 0 {
			de.RequestTemplate = &crawler.RequestTemplate{
				Method: ep.Method, URL: ep.URL, Body: ep.Body,
				ContentType: ep.ContentType, Headers: ep.Headers,
			}
		}
		seeds = append(seeds, de)
	}
	_ = e.Emit("phase_started", "js api crawl", map[string]interface{}{
		"phase": "js_api_crawl", "seeds": len(seeds),
	})
	e.session.SetPhase("js_api_crawl")
	c := crawler.New(e.session.ID, e.session.Config, e.client, e.scope, e.db, e.Emit)
	if e.session.Config.EnableHeadlessCrawler {
		browserHeaders, browserCookies := browserSession(e.session.Config)
		doFn := func(ctx context.Context, method, url string, body []byte, headers map[string]string) (string, error) {
			rr, err := e.client.Do(ctx, method, url, body, headers)
			if err != nil {
				return "", err
			}
			return rr.Response.Body, nil
		}
		var pool *browserpool.Pool
		if e.platform != nil {
			pool = e.platform.browserPool
		}
		c.SetBrowser(browserpool.NewCrawlerBrowserWithSession(
			pool,
			browserpool.HTTPPageFetcher(doFn),
			e.session.Config.ProxyURL,
			e.session.Config.InsecureSkipVerify,
			browserHeaders,
			browserCookies,
		))
	}
	budget := crawler.Budget{
		MaxDepth: e.session.Config.MaxDepth,
		MaxPages: e.session.Config.MaxPages,
	}
	if err := c.CrawlEndpointSeeds(ctx, seeds, budget); err != nil {
		return err
	}
	pages, requests, discovered := c.Stats()
	runtimeEndpoints := c.RuntimeCoverage()
	e.session.Increment("browser_runtime_endpoints", runtimeEndpoints)
	_ = e.Emit("phase_finished", "js api crawl", map[string]interface{}{
		"phase": "js_api_crawl", "seeds": len(seeds),
		"pages": pages, "requests": requests, "discovered": discovered,
		"browser_runtime_endpoints": runtimeEndpoints,
	})
	return nil
}
