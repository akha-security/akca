package crawler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/findingevent"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/queue"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/secretscan"
	"github.com/akha-security/akca/engine/internal/stategraph"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/urlutil"
)

// maxSecretScanBytes caps how much of a response body is scanned for secrets to
// avoid pathological CPU usage on very large assets.
const maxSecretScanBytes = 3 * 1024 * 1024

var ErrIncomplete = errors.New("crawl incomplete")

type HTTPDoer interface {
	Do(ctx context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error)
}

type Crawler struct {
	mu               sync.Mutex
	scanID           string
	cfg              config.ScanConfig
	client           HTTPDoer
	scope            *scope.Engine
	db               *storage.DB
	q                *queue.RequestQueue
	seen             map[string]struct{}
	recorded         map[string]struct{}
	runtimeSeen      map[string]struct{}
	secretsSeen      map[string]struct{}
	queryVariants    map[string]map[string]struct{}
	linkedHostsSeen  map[string]struct{}
	browserBlocked   map[string]struct{}
	seeds            []string
	emit             EventSink
	browser          BrowserFetcher
	pagesVisited     int
	contentPages     int
	rejectedPages    int
	networkErrors    int
	requestsMade     int
	discovered       int
	runtimeFound     int
	browserAttempts  int
	browserRecovered int
	failures         int
	startedAt        time.Time
	eventBatch       []map[string]interface{}
	stateGraph       *stategraph.Graph
}

func New(scanID string, cfg config.ScanConfig, client HTTPDoer, scopeEngine *scope.Engine, db *storage.DB, emit EventSink) *Crawler {
	if emit == nil {
		emit = func(string, string, map[string]interface{}) error { return nil }
	}
	linked := make(map[string]struct{})
	for _, inc := range cfg.IncludeDomains {
		if host := strings.ToLower(config.NormalizeDomain(inc)); host != "" {
			linked[host] = struct{}{}
		}
	}
	for _, t := range cfg.Targets {
		if u, err := url.Parse(t); err == nil && u.Hostname() != "" {
			linked[strings.ToLower(u.Hostname())] = struct{}{}
		}
	}
	return &Crawler{
		scanID:          scanID,
		cfg:             cfg,
		client:          client,
		scope:           scopeEngine,
		db:              db,
		q:               queue.NewRequestQueue(),
		seen:            make(map[string]struct{}),
		recorded:        make(map[string]struct{}),
		runtimeSeen:     make(map[string]struct{}),
		secretsSeen:     make(map[string]struct{}),
		queryVariants:   make(map[string]map[string]struct{}),
		linkedHostsSeen: linked,
		browserBlocked:  make(map[string]struct{}),
		emit:            emit,
		stateGraph:      stategraph.New(db),
	}
}

func (c *Crawler) SetBrowser(browser BrowserFetcher) {
	c.browser = browser
}

func (c *Crawler) recordBrowserBlocked(resources []string) {
	if len(resources) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.browserBlocked == nil {
		c.browserBlocked = make(map[string]struct{})
	}
	for _, resource := range resources {
		if resource = strings.TrimSpace(resource); resource != "" {
			c.browserBlocked[resource] = struct{}{}
		}
	}
}

// emitBrowserBlockedSummary keeps browser policy gaps useful without printing
// the same warning once for every rendered page. Exact URLs remain internal;
// the event exposes only hostnames so query strings cannot leak credentials.
func (c *Crawler) emitBrowserBlockedSummary() {
	c.mu.Lock()
	resources := make([]string, 0, len(c.browserBlocked))
	for resource := range c.browserBlocked {
		resources = append(resources, resource)
	}
	c.mu.Unlock()
	if len(resources) == 0 {
		return
	}

	hostSet := make(map[string]struct{})
	for _, resource := range resources {
		if parsed, err := url.Parse(resource); err == nil && parsed.Hostname() != "" {
			hostSet[strings.ToLower(parsed.Hostname())] = struct{}{}
		}
	}
	hosts := make([]string, 0, len(hostSet))
	for host := range hostSet {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)

	message := fmt.Sprintf("Browser coverage was limited: %d unique request(s) were blocked by scope or request budget", len(resources))
	if len(hosts) > 0 {
		displayedHosts := hosts
		if len(displayedHosts) > 5 {
			displayedHosts = displayedHosts[:5]
		}
		message += fmt.Sprintf(" across %d host(s) (%s", len(hosts), strings.Join(displayedHosts, ", "))
		if len(displayedHosts) < len(hosts) {
			message += fmt.Sprintf(", and %d more", len(hosts)-len(displayedHosts))
		}
		message += ")"
	}
	message += "; allow only required passive dependency hosts with browser_resource_domains, or increase request_budget if those hosts are already allowed"
	_ = c.emit("coverage_gap", message, map[string]interface{}{
		"phase": "crawling", "reason": "browser_request_policy", "blocked_requests": len(resources), "blocked_hosts": hosts,
	})
}

// IngestSeeds adds explicit in-scope URLs for later crawl phases.
func (c *Crawler) IngestSeeds(urls []string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	added := 0
	for _, raw := range urls {
		if !c.scope.IsInScope(raw) {
			continue
		}
		norm, err := NormalizeURL(raw)
		if err != nil {
			continue
		}
		key := dedupeKey("GET", norm)
		if _, ok := c.seen[key]; ok {
			continue
		}
		if limit := c.cfg.MaxEndpointsLimit(); limit > 0 && len(c.seen) >= limit {
			break
		}
		c.seeds = append(c.seeds, raw)
		c.seen[key] = struct{}{}
		c.q.Enqueue(queue.Item{URL: raw, Method: "GET", Priority: 1000, Depth: 0, Source: string(SourceSeedIngest)})
		added++
	}
	return added
}

func (c *Crawler) Crawl(ctx context.Context, seeds []string) error {
	c.mu.Lock()
	c.startedAt = time.Now()
	c.pagesVisited = 0
	c.contentPages = 0
	c.rejectedPages = 0
	c.networkErrors = 0
	c.requestsMade = 0
	c.discovered = 0
	c.runtimeFound = 0
	c.browserAttempts = 0
	c.browserRecovered = 0
	c.failures = 0
	c.eventBatch = nil
	c.browserBlocked = make(map[string]struct{})
	c.mu.Unlock()

	_ = c.emit("crawler_started", "crawler started", map[string]interface{}{"scan_id": c.scanID})

	if err := c.db.EnsureScan(c.scanID); err != nil {
		return err
	}

	budget := Budget{
		MaxDepth:      c.cfg.MaxDepth,
		MaxPages:      c.cfg.EffectiveMaxPages(),
		RequestBudget: c.cfg.EffectiveCrawlerBudget(),
		TimeBudget:    c.cfg.TimeBudget,
	}
	for _, seed := range seeds {
		c.enqueueCandidate(seed, "GET", 0, SourceSeed, 1.0, "initial seed", budget, nil, "")
	}
	seedQueueSize := c.q.Len()
	c.IngestSeeds(c.seeds)

	c.fetchSpecialPaths(ctx, seeds, budget)
	if c.q.Len() == 0 {
		message := "Crawler has no crawlable in-scope requests; verify the target URL and include/exclude domain rules"
		_ = c.emit("coverage_gap", message, map[string]interface{}{
			"scan_id": c.scanID, "phase": "crawling", "reason": "empty_initial_queue",
			"seed_count": len(seeds), "accepted_seed_requests": seedQueueSize,
		})
		_ = c.emit("crawler_finished", "crawler stopped without requests", map[string]interface{}{
			"scan_id": c.scanID, "pages": 0, "requests": 0, "discovered": c.discovered,
			"has_usable_content": false, "reason": "empty_initial_queue",
		})
		return fmt.Errorf("crawl incomplete: %s", strings.ToLower(message))
	}

	// Surface seed/well-known endpoints right away so the UI shows discoveries
	// before any (potentially slow) network round-trip completes.
	_ = c.flushEndpointEvents()
	_ = c.emit("scan_progress", "crawling", map[string]interface{}{
		"scan_id": c.scanID, "phase": "crawling",
		"queue_size": c.q.Len(), "discovered": c.discovered,
	})

	c.runWorkers(ctx, budget)
	c.emitBrowserBlockedSummary()
	c.mu.Lock()
	contentPages, rejectedPages, networkErrors := c.contentPages, c.rejectedPages, c.networkErrors
	c.mu.Unlock()

	_ = c.flushEndpointEvents()
	_ = c.emit("queue_updated", "crawl workers stopped", map[string]interface{}{
		"scan_id": c.scanID, "queue_size": c.q.Len(), "discovered": c.discovered,
	})
	_ = c.emit("crawler_finished", "crawler finished", map[string]interface{}{
		"scan_id": c.scanID, "pages": c.pagesVisited, "requests": c.requestsMade, "discovered": c.discovered,
		"errors":        c.failureCount(),
		"content_pages": contentPages, "rejected_pages": rejectedPages, "network_errors": networkErrors,
		"browser_attempts": c.browserAttemptCount(), "browser_recovered_pages": c.browserRecoveryCount(),
		"has_usable_content": contentPages > 0,
	})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if c.q.Len() > 0 {
		reason := c.stopReason(budget)
		_ = c.emit("coverage_gap", "Crawl stopped before all queued URLs were visited", map[string]interface{}{"queue_remaining": c.q.Len(), "phase": "crawling", "reason": reason})
		return fmt.Errorf("%w: %d queued URLs remain (%s)", ErrIncomplete, c.q.Len(), reason)
	}
	if contentPages == 0 {
		return fmt.Errorf("crawl incomplete: no usable page content received (%d rejected responses, %d network errors); check target access, authentication and HTTP responses", rejectedPages, networkErrors)
	}
	if failed := c.failureCount(); failed > 0 {
		return fmt.Errorf("crawler completed with %d persistence errors", failed)
	}
	return nil
}

// runWorkers drains the priority queue with a bounded pool of concurrent
// fetchers. Per-host/global rate limiting is enforced inside the HTTP client, so
// concurrency here only removes the head-of-line blocking that made a single
// slow or timing-out target freeze the whole crawl. A periodic ticker flushes
// pending endpoint discoveries and emits live crawl progress so the UI keeps
// updating even while individual requests are still in flight.
func (c *Crawler) runWorkers(ctx context.Context, budget Budget) {
	workers := crawlerWorkerCount(c.cfg)

	done := make(chan struct{})
	var closeOnce sync.Once
	finish := func() { closeOnce.Do(func() { close(done) }) }

	progressStop := make(chan struct{})
	var progressWG sync.WaitGroup
	progressWG.Add(1)
	go func() {
		defer progressWG.Done()
		t := time.NewTicker(750 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-progressStop:
				return
			case <-t.C:
				_ = c.flushEndpointEvents()
				pages, requests, discovered := c.Stats()
				_ = c.emit("scan_progress", "crawling", map[string]interface{}{
					"scan_id": c.scanID, "phase": "crawling",
					"pages": pages, "requests": requests,
					"discovered": discovered, "queue_size": c.q.Len(),
				})
			}
		}
	}()

	var workMu sync.Mutex
	active := 0
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					_ = c.emit("log", fmt.Sprintf("crawler worker recovered from panic: %v", r), map[string]interface{}{
						"scan_id": c.scanID,
					})
					finish()
				}
			}()
			for {
				select {
				case <-ctx.Done():
					finish()
					return
				case <-done:
					return
				default:
				}
				if c.budgetExceeded(budget) {
					finish()
					return
				}

				// Dequeue and in-flight accounting must be atomic with the drain
				// check; an empty queue alone does not mean discovery is finished.
				workMu.Lock()
				item, ok := c.q.Dequeue()
				if ok {
					active++
				} else if active == 0 {
					finish()
				}
				workMu.Unlock()
				if !ok {
					select {
					case <-done:
						return
					case <-time.After(25 * time.Millisecond):
					}
					continue
				}

				if err := c.visit(ctx, item, budget); err != nil {
					_ = c.emit("log", "request failed: "+err.Error(), map[string]interface{}{
						"scan_id": c.scanID, "url": item.URL, "method": item.Method,
					})
				}
				workMu.Lock()
				active--
				workMu.Unlock()
			}
		}()
	}

	wg.Wait()
	close(progressStop)
	progressWG.Wait()
}

func crawlerWorkerCount(cfg config.ScanConfig) int {
	workers := cfg.MaxConcurrency
	if workers <= 0 {
		workers = 8
	}
	if workers > 48 {
		workers = 48
	}
	return workers
}

func (c *Crawler) visit(ctx context.Context, item queue.Item, budget Budget) (visitErr error) {
	defer func() {
		if r := recover(); r != nil {
			_ = c.emit("log", fmt.Sprintf("crawler visit recovered from panic: %v", r), map[string]interface{}{
				"scan_id": c.scanID, "url": item.URL,
			})
			c.recordFailure()
			visitErr = fmt.Errorf("crawler visit panic: %v", r)
		}
	}()
	rawURL := item.URL
	method := item.Method
	depth := item.Depth
	if method == "" {
		method = http.MethodGet
	}
	if c.budgetExceeded(budget) || (budget.MaxDepth > 0 && depth > budget.MaxDepth) {
		return nil
	}
	if !c.scope.IsInScope(rawURL) {
		return nil
	}
	if IsCrawlerTrap(rawURL) {
		return nil
	}

	source := DiscoverySource(item.Source)
	if source == "" {
		source = SourceLink
	}
	why := item.Why
	if why == "" {
		why = "visited page"
	}

	reqHeaders := cloneHeaderMap(item.Headers)
	if method == http.MethodGet {
		if reqHeaders == nil {
			reqHeaders = map[string]string{}
		}
		setHeaderDefault(reqHeaders, "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		setHeaderDefault(reqHeaders, "Accept-Language", "en-US,en;q=0.9")
		setHeaderDefault(reqHeaders, "Sec-Fetch-Mode", "navigate")
		setHeaderDefault(reqHeaders, "Sec-Fetch-Dest", "document")
		setHeaderDefault(reqHeaders, "Upgrade-Insecure-Requests", "1")
	}
	reqBody := append([]byte(nil), item.Body...)
	visitURL := rawURL
	if method == http.MethodGet && len(reqBody) == 0 && item.Headers == nil {
		// GET with query already encoded in URL from form templates.
	} else if method == http.MethodGet && strings.Contains(rawURL, "?") {
		visitURL = rawURL
	}

	if !c.reserveRequest(budget) {
		c.q.Enqueue(item)
		return nil
	}
	rr, err := c.client.Do(ctx, method, visitURL, reqBody, reqHeaders)
	if err != nil {
		c.mu.Lock()
		c.networkErrors++
		c.mu.Unlock()
		return err
	}

	c.mu.Lock()
	c.pagesVisited++
	if rr.Response.StatusCode >= 200 && rr.Response.StatusCode < 300 && strings.TrimSpace(rr.Response.Body) != "" && usableApplicationSource(source) {
		c.contentPages++
	}
	if rr.Response.StatusCode >= 400 {
		c.rejectedPages++
	}
	c.mu.Unlock()
	if (source == SourceSeed || item.Why == "redirect landing page") && rr.Response.StatusCode >= 400 {
		_ = c.emit("coverage_gap", fmt.Sprintf("Crawler could not access %s: HTTP %d (%d response bytes). Discovery is incomplete.", rawURL, rr.Response.StatusCode, len(rr.Response.Body)), map[string]interface{}{
			"phase": "crawling", "url": rawURL, "status_code": rr.Response.StatusCode,
		})
	}
	var endpointID *int64
	if id, idErr := c.db.GetEndpointID(c.scanID, rawURL, method); idErr == nil {
		endpointID = &id
	}
	if c.cfg.EnableRawTrafficStorage {
		if _, saveErr := c.db.SaveRequestResponse(c.scanID, endpointID, rr); saveErr != nil {
			c.recordFailure()
			_ = c.emit("scan_error", "crawler traffic could not be persisted: "+saveErr.Error(), map[string]interface{}{
				"scan_id": c.scanID, "phase": "crawling", "url": rawURL,
			})
		}
	}

	body := rr.Response.Body
	contentType := ""
	for k, v := range rr.Response.Headers {
		if strings.EqualFold(k, "Content-Type") {
			contentType = v
			break
		}
	}

	lowerCT := strings.ToLower(contentType)
	lowerBody := strings.ToLower(body)
	isHTML := strings.Contains(lowerCT, "html") ||
		strings.Contains(lowerCT, "xhtml") ||
		strings.Contains(lowerCT, "xml") ||
		strings.Contains(lowerCT, "text/") ||
		lowerCT == "" ||
		strings.Contains(lowerBody, "<html") ||
		strings.Contains(lowerBody, "<!doctype") ||
		strings.Contains(lowerBody, "<body") ||
		strings.Contains(lowerBody, "<head") ||
		strings.Contains(lowerBody, "<div") ||
		strings.Contains(lowerBody, "<table") ||
		strings.Contains(lowerBody, "<form") ||
		strings.Contains(lowerBody, "<a ") ||
		strings.Contains(lowerBody, "<a\n") ||
		strings.Contains(lowerBody, "<a\t")

	c.recordEndpoint(rawURL, method, source, 1.0, depth, why, &RequestTemplate{
		Method: method, URL: visitURL, Headers: mergeHeaderMaps(reqHeaders, rr.Request.Headers),
		Body: string(reqBody), ContentType: headerContentType(reqHeaders),
		ResponseStatus: rr.Response.StatusCode, ResponseHeaders: rr.Response.Headers,
		ResponseBody: rr.Response.Body, FetchedViaGETFallback: false,
	})

	// Auto-adopt redirect landing hosts into active scope with strict policy (apex <-> www by default)
	if loc := rr.Response.Headers["Location"]; loc != "" {
		if u, err := url.Parse(loc); err == nil && u.Hostname() != "" {
			if curr, err := url.Parse(rawURL); err == nil && curr.Hostname() != "" {
				c.tryAdoptRedirectHost(u.Hostname(), curr.Hostname(), "location_header")
			}
		}
	}
	if rr.Request.URL != "" && rr.Request.URL != visitURL {
		if land, err := url.Parse(rr.Request.URL); err == nil && land.Hostname() != "" {
			if curr, err := url.Parse(visitURL); err == nil && curr.Hostname() != "" {
				c.tryAdoptRedirectHost(land.Hostname(), curr.Hostname(), "final_request_url")
			}
		}
	}

	// Request.URL records the original request; FinalURL is the document base
	// after redirects (including directory redirects such as /app -> /app/).
	pageURL := rawURL
	if finalURL := rr.Response.FinalURL; finalURL != "" && c.scope.IsInScope(finalURL) {
		pageURL = finalURL
	}
	if c.cfg.FollowRedirects && rr.Response.StatusCode >= 300 && rr.Response.StatusCode < 400 {
		for name, location := range rr.Response.Headers {
			if !strings.EqualFold(name, "Location") {
				continue
			}
			if landing, err := ResolveReference(pageURL, location); err == nil && landing != "" {
				from, _ := url.Parse(pageURL)
				to, _ := url.Parse(landing)
				if from != nil && to != nil {
					c.tryAdoptRedirectHost(to.Hostname(), from.Hostname(), "location_header")
				}
				c.enqueueCandidate(landing, http.MethodGet, depth, SourceLink, 1, "redirect landing page", budget, nil, rawURL)
			}
		}
	}
	for _, linkURL := range extractLinkHeaderURLs(pageURL, rr.Response.Headers) {
		c.enqueueCandidate(linkURL, http.MethodGet, depth+1, SourceLinkHeader, 0.75, "Link response header", budget, nil, rawURL)
	}

	// Scan every response body (HTML, JSON, JS, plain text, …) for leaked
	// secrets and compromised supply chain scripts (Polyfill.io / CWE-829).
	c.scanSecrets(rawURL, body)
	c.scanSupplyChain(rawURL, body)
	c.scanThirdPartyScriptIntegrity(rawURL, body)

	isJS := strings.Contains(lowerCT, "javascript") || strings.Contains(lowerCT, "ecmascript") ||
		strings.HasSuffix(strings.ToLower(rawURL), ".js") || strings.HasSuffix(strings.ToLower(rawURL), ".mjs")

	var discovered []DiscoveredEndpoint
	if isHTML {
		discovered = append(discovered, ExtractFromHTML(pageURL, body)...)
		discovered = append(discovered, ExtractManifestAndServiceWorker(pageURL, body)...)
		// Inline <script> blocks frequently contain fetch/axios/XHR calls.
		discovered = append(discovered, ExtractASTFromJSBundle(pageURL, body)...)
	}
	if isJS {
		discovered = append(discovered, ExtractFromJSBundle(pageURL, body)...)
		// AST pass complements the regex pass for multiline/template-literal calls.
		discovered = append(discovered, ExtractASTFromJSBundle(pageURL, body)...)
	}
	if strings.Contains(strings.ToLower(rawURL), "robots.txt") {
		discovered = append(discovered, ExtractFromRobots(rawURL, body)...)
	}
	if strings.Contains(strings.ToLower(rawURL), "sitemap") {
		discovered = append(discovered, ExtractFromSitemap(body)...)
	}

	var browserState *BrowserSnapshot
	hasScripts := strings.Contains(strings.ToLower(body), "<script")
	// Retry browser-only authentication and anti-bot responses once through the
	// configured browser. Do not launch browsers for speculative API-doc probes.
	deniedDocument := browserRecoverableDocumentStatus(rr.Response.StatusCode) && method == http.MethodGet &&
		(source == SourceSeed || source == SourceSeedIngest || source == SourceLink || source == SourceBrowserXHR)
	if ((isHTML && hasScripts) || deniedDocument) && c.cfg.EnableHeadlessCrawler && c.browser != nil {
		c.mu.Lock()
		c.browserAttempts++
		c.mu.Unlock()
		if instrumented, ok := c.browser.(InstrumentedBrowserFetcher); ok {
			snapshot, browserErr := instrumented.FetchInstrumented(ctx, rawURL)
			c.recordBrowserBlocked(snapshot.BlockedResources)
			if deniedDocument && browserErr == nil {
				if snapshot.DocumentStatus < 200 || snapshot.DocumentStatus >= 300 ||
					strings.TrimSpace(snapshot.DOM) == "" || !c.scope.IsInScope(snapshot.URL) {
					browserErr = fmt.Errorf("browser did not return a successful in-scope document (HTTP %d)", snapshot.DocumentStatus)
				} else {
					c.mu.Lock()
					c.contentPages++
					c.browserRecovered++
					c.mu.Unlock()
					c.recordEndpoint(rawURL, method, source, 1, depth, "browser document after HTTP rejection", &RequestTemplate{
						Method: method, URL: snapshot.URL, ResponseStatus: snapshot.DocumentStatus,
						ResponseBody: snapshot.DOM, ResponseHeaders: map[string]string{"Content-Type": "text/html"},
					})
					_ = c.emit("log", "Crawler recovered page content through browser navigation", map[string]interface{}{"url": rawURL, "phase": "crawling"})
				}
			}
			if browserErr != nil {
				_ = c.emit("coverage_gap", "Browser discovery unavailable: "+browserErr.Error(), map[string]interface{}{"url": rawURL, "phase": "crawling"})
			}
			if browserErr == nil {
				c.adoptBrowserCookies(snapshot.Cookies)
				browserState = &snapshot
				discovered = append(discovered, snapshot.NetworkCalls...)
				base := pageURL
				if snapshot.URL != "" && c.scope.IsInScope(snapshot.URL) {
					base = snapshot.URL
				}
				discovered = append(discovered, ExtractFromHTML(base, snapshot.DOM)...)
			}
		} else if !deniedDocument {
			dom, xhr, browserErr := c.browser.Fetch(ctx, rawURL)
			if browserErr == nil {
				discovered = append(discovered, xhr...)
				discovered = append(discovered, ExtractFromHTML(pageURL, dom)...)
			}
		}
	}

	apiCalls := make([]string, 0, len(discovered))
	for _, ep := range discovered {
		if ep.Source == SourceBrowserXHR || ep.Source == SourceGraphQL || ep.Source == SourceWebSocket ||
			ep.Source == SourceEventSource || strings.Contains(strings.ToLower(ep.URL), "/api/") {
			apiCalls = append(apiCalls, ep.URL)
		}
	}
	identity := c.graphIdentity()
	graphHTML := body
	var cookies, sessionStorage, localStorage map[string]string
	var actions, forms, webSockets []string
	if browserState != nil {
		if browserState.DOM != "" {
			graphHTML = browserState.DOM
		}
		cookies, sessionStorage, localStorage = browserState.Cookies, browserState.SessionStorage, browserState.LocalStorage
		actions, forms, webSockets = browserState.VisibleActions, browserState.Forms, browserState.WebSockets
		apiCalls = append(apiCalls, browserState.ServiceWorkers...)
	}
	var serviceWorkers, domSinkEvents []string
	if browserState != nil {
		serviceWorkers, domSinkEvents = browserState.ServiceWorkers, browserState.DOMSinkEvents
	}
	node, graphErr := c.stateGraph.ObserveInstrumentedPage(c.scanID, rawURL, graphHTML, identity,
		cookies, sessionStorage, localStorage, actions, forms, apiCalls, webSockets, serviceWorkers, domSinkEvents)
	if graphErr == nil {
		fromID := ""
		if item.ParentURL != "" {
			if parent, ok := c.stateGraph.FindByURL(item.ParentURL, identity); ok {
				fromID = parent.ID
			}
		}
		_, _ = c.stateGraph.AddTransition(c.scanID, fromID, node.ID,
			strings.ToLower(method)+" "+string(source),
			map[string]interface{}{"method": method, "url": visitURL, "headers": reqHeaders, "body": string(reqBody)},
			nil, nil, method == http.MethodGet || method == http.MethodHead)
	}

	for _, ep := range discovered {
		c.enqueueCandidate(ep.URL, ep.Method, depth+1, ep.Source, ep.Confidence, ep.WhyDiscovered, budget, ep.RequestTemplate, rawURL)
	}
	return nil
}

func browserRecoverableDocumentStatus(status int) bool {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return true
	default:
		return false
	}
}

type crawlSessionUpdater interface {
	SetSession(cookies map[string]string, headers map[string]string)
}

// adoptBrowserCookies carries cookies created during a browser navigation
// (login redirects, anti-bot clearance, SPA bootstrap) into later HTTP crawl
// requests. Ambiguous CDP keys use "domain|name" and are not valid Cookie
// header names, so they are deliberately skipped.
func (c *Crawler) adoptBrowserCookies(cookies map[string]string) {
	if len(cookies) == 0 {
		return
	}
	clean := make(map[string]string, len(cookies))
	for name, value := range cookies {
		name = strings.TrimSpace(name)
		if name == "" || strings.ContainsAny(name, "|;=\r\n") {
			continue
		}
		clean[name] = value
	}
	if len(clean) == 0 {
		return
	}
	if updater, ok := c.client.(crawlSessionUpdater); ok {
		updater.SetSession(clean, nil)
	}
}

func (c *Crawler) graphIdentity() string {
	if len(c.cfg.AuthProfiles) > 0 {
		if id := strings.TrimSpace(c.cfg.AuthProfiles[0].ID); id != "" {
			return "auth_profile:" + id
		}
		return "auth_profile:default"
	}
	if len(c.cfg.SessionCookies) > 0 || len(c.cfg.Authentication) > 0 {
		return "default_authenticated"
	}
	for key := range c.cfg.CustomHeaders {
		if strings.EqualFold(key, "Authorization") || strings.EqualFold(key, "X-API-Key") ||
			strings.EqualFold(key, "X-Auth-Token") {
			return "default_authenticated"
		}
	}
	return "anonymous"
}

func setHeaderDefault(headers map[string]string, name, value string) {
	for key := range headers {
		if strings.EqualFold(key, name) {
			return
		}
	}
	headers[name] = value
}

func cloneHeaderMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func mergeHeaderMaps(a, b map[string]string) map[string]string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	out := cloneHeaderMap(a)
	if out == nil {
		out = make(map[string]string, len(b))
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func headerContentType(headers map[string]string) string {
	for k, v := range headers {
		if strings.EqualFold(k, "Content-Type") {
			return v
		}
	}
	return ""
}

func (c *Crawler) fetchSpecialPaths(_ context.Context, seeds []string, budget Budget) {
	for _, seed := range seeds {
		base := strings.TrimRight(seed, "/")
		origin := base
		if u, err := url.Parse(seed); err == nil && u.Scheme != "" && u.Host != "" {
			origin = u.Scheme + "://" + u.Host
		}
		for _, ep := range CommonAPIDocPaths(origin) {
			c.enqueueCandidate(ep.URL, ep.Method, 0, ep.Source, ep.Confidence, ep.WhyDiscovered, budget, nil, "")
		}
		if origin != base {
			for _, ep := range CommonAPIDocPaths(base) {
				c.enqueueCandidate(ep.URL, ep.Method, 0, ep.Source, ep.Confidence, ep.WhyDiscovered, budget, nil, "")
			}
		}
		c.enqueueCandidate(origin+"/robots.txt", http.MethodGet, 0, SourceRobots, 0.9, "well-known robots.txt", budget, nil, "")
		c.enqueueCandidate(origin+"/sitemap.xml", http.MethodGet, 0, SourceSitemap, 0.9, "well-known sitemap.xml", budget, nil, "")
		if origin != base {
			c.enqueueCandidate(base+"/robots.txt", http.MethodGet, 0, SourceRobots, 0.9, "app path robots.txt", budget, nil, "")
			c.enqueueCandidate(base+"/sitemap.xml", http.MethodGet, 0, SourceSitemap, 0.9, "app path sitemap.xml", budget, nil, "")
		}
	}
}

// CrawlEndpointSeeds enqueues discovered endpoints with their HTTP methods (used for JS API re-crawl).
func (c *Crawler) CrawlEndpointSeeds(ctx context.Context, seeds []DiscoveredEndpoint, budget Budget) error {
	c.mu.Lock()
	c.startedAt = time.Now()
	c.mu.Unlock()
	if budget.MaxDepth <= 0 && c.cfg.MaxDepth > 0 {
		budget.MaxDepth = c.cfg.MaxDepth
	}
	for _, ep := range seeds {
		c.enqueueCandidate(ep.URL, ep.Method, 0, ep.Source, ep.Confidence, ep.WhyDiscovered, budget, ep.RequestTemplate, "")
	}
	c.runWorkers(ctx, budget)
	_ = c.flushEndpointEvents()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if c.q.Len() > 0 || c.failureCount() > 0 {
		return fmt.Errorf("JS crawl incomplete: %d queued URLs, %d persistence/worker errors", c.q.Len(), c.failureCount())
	}
	return nil
}

func (c *Crawler) enqueueCandidate(rawURL, method string, depth int, source DiscoverySource, confidence float64, why string, budget Budget, tmpl *RequestTemplate, parentURL string) {
	if rawURL == "" || !urlutil.IsPlausibleEndpointURL(rawURL) {
		return
	}
	if method == "" {
		method = "GET"
	}
	if !c.scope.IsInScope(rawURL) {
		return
	}
	if IsCrawlerTrap(rawURL) {
		c.recordEndpoint(rawURL, method, source, confidence, depth, "discovered; excluded by structural URL limit", tmpl)
		if c.emit != nil {
			_ = c.emit("url_skipped", fmt.Sprintf("bounded by crawler trap heuristic: %s", rawURL), map[string]interface{}{
				"url":    rawURL,
				"reason": "skipped_crawler_trap",
			})
		}
		return
	}

	// When a newly discovered linked host/subdomain is encountered, probe its API docs & robots.txt
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		host := strings.ToLower(u.Hostname())
		c.mu.Lock()
		if _, seenHost := c.linkedHostsSeen[host]; !seenHost {
			c.linkedHostsSeen[host] = struct{}{}
			c.mu.Unlock()
			scheme := u.Scheme
			if scheme == "" {
				scheme = "https"
			}
			apiOrigin := scheme + "://" + u.Host
			for _, ep := range CommonAPIDocPaths(apiOrigin) {
				c.enqueueCandidate(ep.URL, ep.Method, depth, ep.Source, ep.Confidence, ep.WhyDiscovered, budget, nil, rawURL)
			}
			c.enqueueCandidate(apiOrigin+"/robots.txt", http.MethodGet, depth, SourceRobots, 0.85, "linked host robots.txt", budget, nil, rawURL)
		} else {
			c.mu.Unlock()
		}
	}

	norm, err := NormalizeURL(rawURL)
	if err != nil {
		return
	}
	key := dedupeKey(method, norm)
	c.mu.Lock()
	if _, ok := c.seen[key]; ok {
		c.mu.Unlock()
		return
	}
	// The hard endpoint cap applies to queued candidates, not only successfully
	// visited endpoints. Counting only c.discovered allowed a single page with a
	// huge link set to allocate an effectively unbounded queue before any of the
	// links had been fetched.
	if limit := c.cfg.MaxEndpointsLimit(); limit > 0 && len(c.seen) >= limit {
		c.mu.Unlock()
		return
	}
	// Explicitly bounded crawls retain a per-route variant guard so a faceted
	// route cannot consume the entire user-selected budget. Exhaustive Full Scan
	// has no implicit variant cap.
	if c.discoveryIsBounded(budget) && !c.acceptQueryVariantLocked(norm, method) {
		c.mu.Unlock()
		return
	}
	c.seen[key] = struct{}{}
	c.mu.Unlock()

	ep := DiscoveredEndpoint{
		URL: rawURL, Method: method, NormalizedURL: norm, Source: source,
		Confidence: confidence, Depth: depth, WhyDiscovered: why,
	}
	ep.Priority = ScoreEndpoint(ep)
	// Fetch entry pages before speculative API-doc paths consume the budget.
	if source == SourceSeed || source == SourceSeedIngest || why == "redirect landing page" {
		ep.Priority = 1000
	}
	c.recordEndpoint(rawURL, method, source, confidence, depth, why, previewTemplate(rawURL, method, tmpl))
	if method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions {
		return
	}
	// Skip enqueuing static binary assets (images, fonts, media, binary downloads, css) into the active crawl queue.
	// They do not contain navigable links, HTML, or scripts to parse.
	if isStaticMediaAsset(rawURL) {
		return
	}
	// Endpoints discovered beyond the configured depth are still recorded for
	// reporting, but we do not crawl them further to respect MaxDepth.
	if budget.MaxDepth > 0 && depth > budget.MaxDepth {
		c.mu.Lock()
		delete(c.seen, key)
		c.mu.Unlock()
		return
	}
	// Low confidence candidates (< 0.50) or low-confidence SPA guesses are recorded for reporting
	// but not actively fetched to prevent crawling arbitrary noise.
	if confidence < 0.50 || (source == SourceSPARoute && confidence < 0.65) {
		c.mu.Lock()
		delete(c.seen, key)
		c.mu.Unlock()
		return
	}
	item := queue.Item{
		URL: rawURL, Method: method, Priority: ep.Priority, Depth: depth,
		Source: string(source), Why: why, ParentURL: parentURL,
	}
	if tmpl != nil {
		item.Body = []byte(tmpl.Body)
		item.Headers = cloneHeaderMap(tmpl.Headers)
		if item.Headers == nil && tmpl.ContentType != "" {
			item.Headers = map[string]string{"Content-Type": tmpl.ContentType}
		}
		if method == http.MethodGet && tmpl.URL != "" {
			item.URL = tmpl.URL
		}
	}
	c.q.Enqueue(item)
}

func (c *Crawler) discoveryIsBounded(budget Budget) bool {
	return budget.MaxPages > 0 || budget.RequestBudget > 0 || c.cfg.MaxEndpointsLimit() > 0
}

// acceptQueryVariantLocked must be called with c.mu held.
func (c *Crawler) acceptQueryVariantLocked(normalizedURL, method string) bool {
	route, variant := routeQueryVariant(normalizedURL, method)
	if route == "" {
		return true
	}
	variants := c.queryVariants[route]
	if variants == nil {
		variants = make(map[string]struct{})
		c.queryVariants[route] = variants
	}
	if _, exists := variants[variant]; exists {
		return true
	}
	if len(variants) >= maxRouteQueryVariants {
		return false
	}
	variants[variant] = struct{}{}
	return true
}

func previewTemplate(rawURL, method string, tmpl *RequestTemplate) *RequestTemplate {
	if tmpl == nil {
		return nil
	}
	out := *tmpl
	if out.URL == "" {
		out.URL = rawURL
	}
	if out.Method == "" {
		out.Method = method
	}
	return &out
}

func (c *Crawler) recordEndpoint(rawURL, method string, source DiscoverySource, confidence float64, depth int, why string, tmpl *RequestTemplate) {
	norm, err := NormalizeURL(rawURL)
	if err != nil {
		return
	}
	if tmpl != nil && len(tmpl.ResponseBody) > 4096 {
		tmpl.ResponseBody = tmpl.ResponseBody[:4096] + "...[truncated]"
	}

	isSeed := source == SourceSeed
	hasFailedStatus := tmpl != nil && (tmpl.ResponseStatus == 404 || tmpl.ResponseStatus == 410)

	// If it returned a 404/410, it's not a real/accessible URL.
	// Keep 400 responses: API routes often return Bad Request until required
	// parameters or body templates are supplied.
	// Delete it from endpoints table if it was previously saved.
	if hasFailedStatus {
		if !isSeed {
			_, _ = c.db.Conn().Exec(
				"DELETE FROM endpoints WHERE scan_id = ? AND url = ? AND method = ? AND COALESCE(discovery_source,'') <> 'api_import'",
				c.scanID, rawURL, method,
			)
			key := dedupeKey(method, norm)
			c.mu.Lock()
			if _, alreadyRecorded := c.recorded[key]; alreadyRecorded {
				delete(c.recorded, key)
				if c.discovered > 0 {
					c.discovered--
				}
			}
			c.mu.Unlock()
		}
		return
	}

	// Discovery is retained even when depth, confidence or budget prevents a visit.

	ep := DiscoveredEndpoint{
		URL: rawURL, Method: method, NormalizedURL: norm, Source: source,
		Confidence: confidence, Depth: depth, WhyDiscovered: why, RequestTemplate: tmpl,
	}

	key := dedupeKey(method, norm)

	c.mu.Lock()
	_, alreadyRecorded := c.recorded[key]
	if runtimeDiscoverySource(source) {
		if _, seenAtRuntime := c.runtimeSeen[key]; !seenAtRuntime {
			c.runtimeSeen[key] = struct{}{}
			c.runtimeFound++
		}
	}
	c.mu.Unlock()

	if alreadyRecorded && tmpl == nil {
		return
	}

	if c.db != nil {
		if err := c.db.SaveDiscoveredEndpoint(c.scanID, ep); err != nil {
			c.recordFailure()
			_ = c.emit("scan_error", "crawler endpoint could not be persisted: "+err.Error(), map[string]interface{}{
				"scan_id": c.scanID, "phase": "crawling", "url": rawURL, "method": method,
			})
			return
		}
	}

	c.mu.Lock()
	if !alreadyRecorded {
		c.recorded[key] = struct{}{}
		c.discovered++
		c.eventBatch = append(c.eventBatch, map[string]interface{}{
			"url": norm, "method": method, "source": string(source), "confidence": confidence,
		})
	}
	shouldFlush := len(c.eventBatch) >= 25
	c.mu.Unlock()
	if shouldFlush {
		_ = c.flushEndpointEvents()
	}
}

// scanSecrets inspects a response body for leaked credentials and records each
// unique finding once per scan.
func (c *Crawler) scanSecrets(sourceURL, body string) {
	if !c.cfg.AllowsModule("secret_exposure") || body == "" {
		return
	}
	content := body
	if len(content) > maxSecretScanBytes {
		content = content[:maxSecretScanBytes]
	}
	for _, m := range secretscan.Detect(content) {
		if !secretscan.IsReportable(m) {
			continue
		}
		key := m.Kind + "|" + m.Value
		c.mu.Lock()
		if _, ok := c.secretsSeen[key]; ok {
			c.mu.Unlock()
			continue
		}
		c.secretsSeen[key] = struct{}{}
		c.mu.Unlock()

		sev := secretscan.Severity(m.Confidence)
		title := "Secret exposed in response (" + m.Kind + ")"
		desc := m.Kind + " detected in response body: " + m.Value
		evidence := secretscan.EvidenceJSONWithResponse(m.Kind, m.Value, sourceURL, m.Line, content)
		findingID, err := c.db.SaveFinding(c.scanID,
			title,
			sev,
			"secret_exposure",
			desc,
			sourceURL, "", m.Confidence, evidence)
		if err != nil {
			_ = c.emit("log", "passive secret finding could not be persisted", map[string]interface{}{
				"scan_id": c.scanID, "url": sourceURL, "kind": m.Kind, "error": err.Error(),
			})
			continue
		}
		_ = c.emit("finding_detected", title, findingevent.Payload(findingevent.Data{
			FindingID: findingID, ScanID: c.scanID, Title: title, Severity: sev,
			VulnClass: "secret_exposure", Endpoint: sourceURL, Location: "response_body",
			Method: "GET", Payload: m.Value, Signal: "passive_secret", Score: m.Confidence,
			Passive: true,
		}))
		_ = c.emit("secret_detected", m.Kind, map[string]interface{}{
			"scan_id": c.scanID, "kind": m.Kind, "redacted": m.Redacted,
			"value": m.Value,
			"url":   sourceURL, "confidence": m.Confidence, "line": m.Line,
			"severity": sev, "title": title,
			"vuln_class": "secret_exposure", "endpoint": sourceURL,
		})
	}
}

var supplyChainBadDomains = []struct {
	domain string
	name   string
}{
	{"polyfill.io", "Polyfill.io Supply Chain Domain (CWE-829)"},
	{"bootcdn.net", "Compromised BootCDN Supply Chain Domain (CWE-829)"},
	{"bootcss.com", "Compromised BootCSS Supply Chain Domain (CWE-829)"},
	{"staticfile.org", "Compromised StaticFile Supply Chain Domain (CWE-829)"},
	{"staticfile.net", "Compromised StaticFile Supply Chain Domain (CWE-829)"},
	{"kuery.net", "Compromised Kuery.net Supply Chain Domain (CWE-829)"},
}

func (c *Crawler) scanSupplyChain(sourceURL, body string) {
	if body == "" || len(body) > maxSecretScanBytes {
		return
	}
	for _, bad := range supplyChainBadDomains {
		if responseReferencesDomain(body, bad.domain) {
			key := "supply_chain|" + bad.domain
			c.mu.Lock()
			if _, ok := c.secretsSeen[key]; ok {
				c.mu.Unlock()
				continue
			}
			c.secretsSeen[key] = struct{}{}
			c.mu.Unlock()

			title := "Supply Chain Security Risk: " + bad.name
			sev := "high"
			desc := "The page references a known compromised third-party script/CDN domain (" + bad.domain + ") vulnerable to supply chain attacks (CWE-829)."
			evidenceBytes, _ := json.Marshal(map[string]interface{}{
				"module": "supply_chain", "signal": "compromised_supply_chain_domain",
				"payload": map[string]string{"value": bad.domain}, "location": "response_body",
				"request":          map[string]string{"method": "GET", "url": sourceURL},
				"resp_body":        body,
				"response_markers": []string{bad.domain}, "cwe": "CWE-829",
			})
			evidence := string(evidenceBytes)
			findingID, err := c.db.SaveFinding(c.scanID, title, sev, "supply_chain", desc, sourceURL, "", 0.95, evidence)
			if err == nil {
				_ = c.emit("finding_detected", title, findingevent.Payload(findingevent.Data{
					FindingID: findingID, ScanID: c.scanID, Title: title, Severity: sev,
					VulnClass: "supply_chain", Endpoint: sourceURL, Location: "script_source",
					Method: "GET", Payload: bad.domain, Signal: "compromised_supply_chain_domain", Score: 0.95,
					Passive: true,
				}))
			}
		}
	}
}

var externalURLRe = regexp.MustCompile(`(?i)(?:https?:)?//[^\s"'<>]+`)
var scriptTagRe = regexp.MustCompile(`(?is)<script\b([^>]*)>`)
var scriptSrcAttributeRe = regexp.MustCompile(`(?i)\bsrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))`)
var integrityAttributeRe = regexp.MustCompile(`(?i)\bintegrity\s*=\s*(?:"[^"]+"|'[^']+'|[^\s>]+)`)

func (c *Crawler) scanThirdPartyScriptIntegrity(sourceURL, body string) {
	if body == "" || len(body) > maxSecretScanBytes {
		return
	}
	page, err := url.Parse(sourceURL)
	if err != nil || page.Hostname() == "" {
		return
	}
	for _, match := range scriptTagRe.FindAllStringSubmatch(body, -1) {
		if len(match) < 2 || integrityAttributeRe.MatchString(match[1]) {
			continue
		}
		src := scriptSource(match[1])
		if src == "" {
			continue
		}
		scriptURL, err := page.Parse(src)
		if err != nil || scriptURL.Hostname() == "" || sameHost(scriptURL.Hostname(), page.Hostname()) {
			continue
		}
		// Known compromised CDNs are already reported with a higher-confidence,
		// high-severity signal.  Do not add a weaker duplicate.
		if isKnownSupplyChainDomain(scriptURL.Hostname()) {
			continue
		}
		key := "third_party_script_without_sri|" + strings.ToLower(scriptURL.String())
		c.mu.Lock()
		if _, ok := c.secretsSeen[key]; ok {
			c.mu.Unlock()
			continue
		}
		c.secretsSeen[key] = struct{}{}
		c.mu.Unlock()

		title := "Third-party script is missing Subresource Integrity"
		desc := "The page loads a third-party script without an integrity attribute. A compromised CDN or package publisher could alter code executed by visitors."
		marker := src
		evidenceBytes, _ := json.Marshal(map[string]interface{}{
			"module": "supply_chain", "signal": "third_party_script_missing_sri",
			"payload": map[string]string{"value": marker}, "location": "response_body",
			"request":          map[string]string{"method": "GET", "url": sourceURL},
			"resp_body":        body,
			"response_markers": []string{marker}, "script_url": scriptURL.String(),
			"control": "subresource_integrity", "cwe": "CWE-353",
		})
		evidence := string(evidenceBytes)
		findingID, err := c.db.SaveFinding(c.scanID, title, "low", "supply_chain", desc, sourceURL, "", 0.78, evidence)
		if err != nil {
			_ = c.emit("log", "passive SRI finding could not be persisted", map[string]interface{}{
				"scan_id": c.scanID, "url": sourceURL, "script_url": scriptURL.String(), "error": err.Error(),
			})
			continue
		}
		_ = c.emit("finding_detected", title, findingevent.Payload(findingevent.Data{
			FindingID: findingID, ScanID: c.scanID, Title: title, Severity: "low",
			VulnClass: "supply_chain", Endpoint: sourceURL, Location: "script_source",
			Method: "GET", Payload: scriptURL.String(), Signal: "third_party_script_missing_sri", Score: 0.78,
			Passive: true,
		}))
	}
}

func scriptSource(attributes string) string {
	match := scriptSrcAttributeRe.FindStringSubmatch(attributes)
	if len(match) == 0 {
		return ""
	}
	for _, value := range match[1:] {
		if value != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func sameHost(left, right string) bool {
	return strings.EqualFold(strings.TrimSuffix(left, "."), strings.TrimSuffix(right, "."))
}

func isKnownSupplyChainDomain(host string) bool {
	host = strings.ToLower(host)
	for _, bad := range supplyChainBadDomains {
		if host == bad.domain || strings.HasSuffix(host, "."+bad.domain) {
			return true
		}
	}
	return false
}

// responseReferencesDomain accepts an actual URL reference, not a domain name
// merely mentioned in prose, a comment, or an example string.
func responseReferencesDomain(body, domain string) bool {
	for _, raw := range externalURLRe.FindAllString(body, -1) {
		if strings.HasPrefix(raw, "//") {
			raw = "https:" + raw
		}
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		host := strings.ToLower(u.Hostname())
		domain = strings.ToLower(domain)
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

func (c *Crawler) flushEndpointEvents() error {
	c.mu.Lock()
	batch := c.eventBatch
	c.eventBatch = nil
	c.mu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	return c.emit("endpoint_discovered", "endpoint batch", map[string]interface{}{
		"scan_id": c.scanID, "count": len(batch), "endpoints": batch,
	})
}

func (c *Crawler) budgetExceeded(budget Budget) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if budget.MaxPages > 0 && c.requestsMade >= budget.MaxPages {
		return true
	}
	if budget.RequestBudget > 0 && c.requestsMade >= budget.RequestBudget {
		return true
	}
	if budget.TimeBudget > 0 && time.Since(c.startedAt) >= budget.TimeBudget {
		return true
	}
	return false
}

func (c *Crawler) stopReason(budget Budget) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if budget.MaxPages > 0 && c.requestsMade >= budget.MaxPages {
		return "max_pages_reached"
	}
	if budget.RequestBudget > 0 && c.requestsMade >= budget.RequestBudget {
		return "crawler_request_budget_reached"
	}
	if budget.TimeBudget > 0 && time.Since(c.startedAt) >= budget.TimeBudget {
		return "time_budget_reached"
	}
	return "worker_or_context_stopped"
}

func (c *Crawler) reserveRequest(budget Budget) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if budget.MaxPages > 0 && c.requestsMade >= budget.MaxPages {
		return false
	}
	if budget.RequestBudget > 0 && c.requestsMade >= budget.RequestBudget {
		return false
	}
	if budget.TimeBudget > 0 && time.Since(c.startedAt) >= budget.TimeBudget {
		return false
	}
	c.requestsMade++
	return true
}

func usableApplicationSource(source DiscoverySource) bool {
	return source != SourceRobots && source != SourceSitemap && source != SourceScript && source != SourceAPIDoc
}

func (c *Crawler) Stats() (pages, requests, discovered int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pagesVisited, c.requestsMade, c.discovered
}

func (c *Crawler) recordFailure() {
	c.mu.Lock()
	c.failures++
	c.mu.Unlock()
}

func (c *Crawler) failureCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.failures
}

// RuntimeCoverage reports unique API and realtime endpoints observed by the
// instrumented browser. This makes authenticated SPA coverage independently
// measurable from static link and JavaScript extraction.
func (c *Crawler) RuntimeCoverage() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.runtimeFound
}

func (c *Crawler) browserAttemptCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.browserAttempts
}

func (c *Crawler) browserRecoveryCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.browserRecovered
}

func runtimeDiscoverySource(source DiscoverySource) bool {
	switch source {
	case SourceBrowserXHR, SourceGraphQL, SourceWebSocket, SourceEventSource:
		return true
	default:
		return false
	}
}

func isStaticMediaAsset(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	clean := strings.ToLower(u.Path)
	if i := strings.IndexAny(clean, "?#"); i >= 0 {
		clean = clean[:i]
	}
	for _, ext := range staticNoiseExtensions {
		if strings.HasSuffix(clean, ext) {
			return true
		}
	}
	return false
}

func isApexWwwPair(h1, h2 string) bool {
	h1 = strings.ToLower(strings.TrimSpace(h1))
	h2 = strings.ToLower(strings.TrimSpace(h2))
	if h1 == h2 || h1 == "" || h2 == "" {
		return false
	}
	return h1 == "www."+h2 || h2 == "www."+h1
}

func (c *Crawler) tryAdoptRedirectHost(targetHost, originHost, reason string) {
	targetHost = strings.ToLower(strings.TrimSpace(targetHost))
	originHost = strings.ToLower(strings.TrimSpace(originHost))
	if targetHost == "" || originHost == "" || targetHost == originHost || c.scope == nil {
		return
	}
	// By default, only canonical apex <-> www pairs are adopted automatically.
	// Wider same-root subdomain adoption requires explicit cfg.AutoAdoptSameRootRedirects.
	allowed := isApexWwwPair(targetHost, originHost)
	if !allowed && c.cfg.AutoAdoptSameRootRedirects && scope.SameRootDomain(targetHost, originHost) {
		allowed = true
	}
	if allowed {
		c.scope.AdoptHost(targetHost)
		if c.emit != nil {
			_ = c.emit("scope_expanded", fmt.Sprintf("adopted redirect host %s from %s (%s)", targetHost, originHost, reason), map[string]interface{}{
				"adopted_host": targetHost,
				"origin_host":  originHost,
				"reason":       reason,
			})
		}
	}
}
