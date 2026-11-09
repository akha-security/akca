package app

import (
	"context"

	"github.com/akha-security/akca/engine/internal/crawler"
)

// runJSDiscoveredCrawlPhase crawls API/endpoint URLs extracted from JavaScript
// bundles so authenticated and linked APIs enter the endpoint graph.
func (e *Engine) runJSDiscoveredCrawlPhase(ctx context.Context) (phaseErr error) {
	limit := e.session.Config.EffectiveMaxPages()
	jsEps, err := e.db.ListPendingJSDiscoveredAPIEndpoints(e.session.ID, limit)
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
	defer func() {
		pages, requests, discovered := c.Stats()
		status := "completed"
		if phaseErr != nil {
			status = "partial"
		}
		_ = e.Emit("phase_finished", "js api crawl", map[string]interface{}{
			"phase": "js_api_crawl", "seeds": len(seeds), "status": status,
			"pages": pages, "requests": requests, "discovered": discovered,
		})
	}()
	budget := crawler.Budget{
		MaxDepth:      e.session.Config.MaxDepth,
		MaxPages:      e.session.Config.EffectiveMaxPages(),
		RequestBudget: e.session.Config.EffectiveCrawlerBudget(),
		TimeBudget:    e.session.Config.TimeBudget,
	}
	return c.CrawlEndpointSeeds(ctx, seeds, budget)
}
