package app

import (
	"context"
	"strings"

	"github.com/akha-security/akca/engine/internal/browserpool"
	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/crawler"
)

func (e *Engine) runCrawlerPhase(ctx context.Context, targets []string) error {
	e.session.SetPhase("crawling")
	_ = e.Emit("phase_started", "crawling", map[string]interface{}{"phase": "crawling"})

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
		// A worker pool is optional, but a real Chromium-capable fetcher is
		// not. Without a pool the bridge still executes the local renderer and
		// falls back to the authenticated HTTP fetcher only when Chromium is
		// genuinely unavailable.
		browserPoolSize := e.session.Config.BrowserWorkerPoolSize
		if browserPoolSize <= 0 {
			browserPoolSize = 6
		}
		if e.session.Config.MaxConcurrency > 0 && browserPoolSize > e.session.Config.MaxConcurrency {
			browserPoolSize = e.session.Config.MaxConcurrency
		}
		c.SetBrowser(browserpool.NewCrawlerBrowserWithSessionAndPoolSize(
			pool,
			browserpool.HTTPPageFetcher(doFn),
			e.session.Config.ProxyURL,
			e.session.Config.InsecureSkipVerify,
			browserHeaders,
			browserCookies,
			browserPoolSize,
		))
	}

	if err := c.Crawl(ctx, targets); err != nil {
		return err
	}
	pages, requests, discovered := c.Stats()
	runtimeEndpoints := c.RuntimeCoverage()
	e.session.SetMetric("browser_runtime_endpoints", runtimeEndpoints)
	_ = e.Emit("phase_finished", "crawling", map[string]interface{}{
		"phase": "crawling", "pages": pages, "requests": requests, "discovered": discovered,
		"browser_runtime_endpoints": runtimeEndpoints,
	})
	return nil
}

func browserSession(cfg config.ScanConfig) (map[string]string, map[string]string) {
	headers := make(map[string]string)
	cookies := make(map[string]string)
	for key, value := range cfg.CustomHeaders {
		headers[key] = value
	}
	for key, value := range cfg.SessionCookies {
		cookies[key] = value
	}
	for key, value := range cfg.Authentication {
		if strings.EqualFold(key, "cookie") {
			for cookie, cookieValue := range parseCookieHeader(value) {
				cookies[cookie] = cookieValue
			}
			continue
		}
		headers[key] = value
	}
	for key, value := range cfg.ApiKeys {
		headers[key] = value
	}
	if len(cfg.AuthProfiles) > 0 {
		for key, value := range cfg.AuthProfiles[0].Headers {
			headers[key] = value
		}
		for key, value := range cfg.AuthProfiles[0].Cookies {
			cookies[key] = value
		}
	}
	return headers, cookies
}
