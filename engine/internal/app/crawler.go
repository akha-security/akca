package app

import (
	"context"
	"strconv"
	"strings"

	"github.com/akha-security/akca/engine/internal/browserpool"
	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/crawler"
	"github.com/akha-security/akca/engine/internal/httpclient"
)

func (e *Engine) runCrawlerPhase(ctx context.Context, targets []string) error {
	return e.runCrawlerStage(ctx, targets, true)
}

func (e *Engine) runCrawlerStage(ctx context.Context, targets []string, initial bool) error {
	phase := "crawling_extended"
	deferredHosts := 0
	cfg := e.session.Snapshot().Config
	if initial {
		phase = "crawling"
		// Complete the configured crawl before input discovery and scanning.
		// A small bootstrap inventory is not sufficient coverage for a full scan.
	} else {
		if e.initialCrawlRequests == 0 && e.db != nil {
			if raw, err := e.db.LatestEvidenceJSON(e.session.ID, "initial_crawl_requests_v1"); err == nil {
				e.initialCrawlRequests, _ = strconv.Atoi(raw)
			}
		}
		ctx = httpclient.WithBackgroundDiscovery(ctx)
		if budget := cfg.EffectiveCrawlerBudget(); budget > 0 {
			cfg.CrawlerRequestBudget = budget - e.initialCrawlRequests
			if cfg.CrawlerRequestBudget <= 0 {
				return nil
			}
		}
		if pages := cfg.EffectiveMaxPages(); pages > 0 {
			cfg.MaxPages = pages - e.initialCrawlRequests
			if cfg.MaxPages <= 0 {
				return nil
			}
		}
		eligible := make([]string, 0, len(targets))
		for _, target := range targets {
			if e.client.HostUnderPressure(target) {
				if err := e.client.RecoverHost(ctx, target); err != nil {
					_ = e.Emit("coverage_gap", "extended crawling deferred after WAF/rate-limit response", map[string]interface{}{"module": "crawling", "endpoint": target})
					deferredHosts++
					continue
				}
			}
			eligible = append(eligible, target)
		}
		targets = eligible
		if len(targets) == 0 && deferredHosts > 0 {
			return httpclient.ErrHostDeferred
		}
	}
	e.session.SetPhase(phase)
	_ = e.Emit("phase_started", "crawling", map[string]interface{}{"phase": phase})

	c := crawler.New(e.session.ID, cfg, e.client, e.scope, e.db, e.Emit)
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
		browser := browserpool.NewCrawlerBrowserWithSessionAndPoolSize(
			pool,
			browserpool.HTTPPageFetcher(doFn),
			e.session.Config.ProxyURL,
			e.session.Config.InsecureSkipVerify,
			browserHeaders,
			browserCookies,
			browserPoolSize,
		)
		if !browser.Available() {
			_ = e.Emit("coverage_gap", "Chromium is unavailable; browser-only pages and WAF challenges may remain undiscovered", map[string]interface{}{
				"phase": "crawling", "reason": "browser_runtime_unavailable",
			})
		}
		if e.client != nil {
			browser.SetRequestGuard(e.client.ReserveExternal)
			browser.SetResourceGuard(e.client.ReserveBrowserResource)
		}
		defer browser.Close()
		c.SetBrowser(browser)
	}

	if err := c.Crawl(ctx, targets); err != nil {
		return err
	}
	pages, requests, discovered := c.Stats()
	if initial {
		e.initialCrawlRequests = requests
		if err := e.db.SaveEvidence(e.session.ID, "initial_crawl_requests_v1", strconv.Itoa(requests)); err != nil {
			return err
		}
	}
	runtimeEndpoints := c.RuntimeCoverage()
	if !initial {
		for _, target := range targets {
			if e.client.HostUnderPressure(target) {
				deferredHosts++
			}
		}
	}
	status := "completed"
	if deferredHosts > 0 {
		status = "partial"
	}
	e.session.SetMetric("browser_runtime_endpoints", runtimeEndpoints)
	_ = e.Emit("phase_finished", "crawling", map[string]interface{}{
		"phase": phase, "pages": pages, "requests": requests, "discovered": discovered,
		"browser_runtime_endpoints": runtimeEndpoints, "status": status, "deferred_hosts": deferredHosts,
	})
	if deferredHosts > 0 {
		return httpclient.ErrHostDeferred
	}
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
