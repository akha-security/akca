package crawler

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
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

type HTTPDoer interface {
	Do(ctx context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error)
}

type Crawler struct {
	mu           sync.Mutex
	scanID       string
	cfg          config.ScanConfig
	client       HTTPDoer
	scope        *scope.Engine
	db           *storage.DB
	q            *queue.RequestQueue
	seen         map[string]struct{}
	recorded     map[string]struct{}
	runtimeSeen  map[string]struct{}
	secretsSeen  map[string]struct{}
	seeds        []string
	emit         EventSink
	browser      BrowserFetcher
	pagesVisited int
	requestsMade int
	discovered   int
	runtimeFound int
	startedAt    time.Time
	eventBatch   []map[string]interface{}
	stateGraph   *stategraph.Graph
}

func New(scanID string, cfg config.ScanConfig, client HTTPDoer, scopeEngine *scope.Engine, db *storage.DB, emit EventSink) *Crawler {
	return &Crawler{
		scanID:      scanID,
		cfg:         cfg,
		client:      client,
		scope:       scopeEngine,
		db:          db,
		q:           queue.NewRequestQueue(),
		seen:        make(map[string]struct{}),
		recorded:    make(map[string]struct{}),
		runtimeSeen: make(map[string]struct{}),
		secretsSeen: make(map[string]struct{}),
		emit:        emit,
		stateGraph:  stategraph.New(db),
	}
}

func (c *Crawler) SetBrowser(browser BrowserFetcher) {
	c.browser = browser
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
		c.seeds = append(c.seeds, raw)
		c.seen[key] = struct{}{}
		c.q.Enqueue(queue.Item{URL: raw, Method: "GET", Priority: 100, Depth: 0})
		added++
	}
	return added
}

func (c *Crawler) Crawl(ctx context.Context, seeds []string) error {
	c.mu.Lock()
	c.startedAt = time.Now()
	c.pagesVisited = 0
	c.requestsMade = 0
	c.discovered = 0
	c.eventBatch = nil
	c.mu.Unlock()

	_ = c.emit("crawler_started", "crawler started", map[string]interface{}{"scan_id": c.scanID})

	_ = c.db.EnsureScan(c.scanID)

	budget := Budget{
		MaxDepth:      c.cfg.MaxDepth,
		MaxPages:      c.cfg.EffectiveMaxPages(),
		RequestBudget: c.cfg.RequestBudget,
		TimeBudget:    c.cfg.TimeBudget,
	}
	if budget.MaxDepth <= 0 {
		budget.MaxDepth = 4
	}

	for _, seed := range seeds {
		c.enqueueCandidate(seed, "GET", 0, SourceSeed, 1.0, "initial seed", budget, nil, "")
	}
	c.IngestSeeds(c.seeds)

	c.fetchSpecialPaths(ctx, seeds, budget)

	// Surface seed/well-known endpoints right away so the UI shows discoveries
	// before any (potentially slow) network round-trip completes.
	_ = c.flushEndpointEvents()
	_ = c.emit("scan_progress", "crawling", map[string]interface{}{
		"scan_id": c.scanID, "phase": "crawling",
		"queue_size": c.q.Len(), "discovered": c.discovered,
	})

	c.runWorkers(ctx, budget)

	_ = c.flushEndpointEvents()
	_ = c.emit("queue_updated", "crawl queue drained", map[string]interface{}{
		"scan_id": c.scanID, "queue_size": c.q.Len(), "discovered": c.discovered,
	})
	_ = c.emit("crawler_finished", "crawler finished", map[string]interface{}{
		"scan_id": c.scanID, "pages": c.pagesVisited, "requests": c.requestsMade, "discovered": c.discovered,
	})
	return nil
}

// runWorkers drains the priority queue with a bounded pool of concurrent
// fetchers. Per-host/global rate limiting is enforced inside the HTTP client, so
// concurrency here only removes the head-of-line blocking that made a single
// slow or timing-out target freeze the whole crawl. A periodic ticker flushes
// pending endpoint discoveries and emits live crawl progress so the UI keeps
// updating even while individual requests are still in flight.
func (c *Crawler) runWorkers(ctx context.Context, budget Budget) {
	workers := c.cfg.MaxConcurrency
	if workers <= 0 {
		workers = 8
	}
	if c.cfg.ScanIntensity == "fast" && workers < 16 {
		workers = 16
	}
	if workers > 48 {
		workers = 48
	}

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

	var active int64
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
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

				atomic.AddInt64(&active, 1)
				item, ok := c.q.Dequeue()
				if !ok {
					// No work right now. If no other worker is processing and
					// the queue is empty, no new items can appear -> we are done.
					if atomic.AddInt64(&active, -1) == 0 && c.q.Len() == 0 {
						finish()
						return
					}
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
				atomic.AddInt64(&active, -1)
			}
		}()
	}

	wg.Wait()
	close(progressStop)
	progressWG.Wait()
}

func (c *Crawler) visit(ctx context.Context, item queue.Item, budget Budget) error {
	rawURL := item.URL
	method := item.Method
	depth := item.Depth
	if method == "" {
		method = http.MethodGet
	}
	if c.budgetExceeded(budget) || depth > budget.MaxDepth {
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

	c.mu.Lock()
	c.pagesVisited++
	c.mu.Unlock()

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
		return nil
	}
	rr, err := c.client.Do(ctx, method, visitURL, reqBody, reqHeaders)
	fetchedViaGET := false
	// POST-only endpoints often reject bare POST; fall back to GET for HTML/JS extraction.
	if method == http.MethodPost && (err != nil || rr.Response.StatusCode == http.StatusMethodNotAllowed || rr.Response.StatusCode == http.StatusNotFound) {
		if !c.reserveRequest(budget) {
			return err
		}
		if getRR, gerr := c.client.Do(ctx, http.MethodGet, rawURL, nil, nil); gerr == nil {
			rr = getRR
			err = nil
			fetchedViaGET = true
		}
	}
	if err != nil {
		return err
	}
	var endpointID *int64
	if id, idErr := c.db.GetEndpointID(c.scanID, rawURL, method); idErr == nil {
		endpointID = &id
	}
	_, _ = c.db.SaveRequestResponse(c.scanID, endpointID, rr)

	body := rr.Response.Body
	contentType := ""
	for k, v := range rr.Response.Headers {
		if strings.EqualFold(k, "Content-Type") {
			contentType = v
			break
		}
	}

	lowerCT := strings.ToLower(contentType)
	isHTML := strings.Contains(lowerCT, "html") || strings.Contains(body, "<html")

	c.recordEndpoint(rawURL, method, source, 1.0, depth, why, &RequestTemplate{
		Method: method, URL: visitURL, Headers: mergeHeaderMaps(reqHeaders, rr.Request.Headers),
		Body: string(reqBody), ContentType: headerContentType(reqHeaders),
		ResponseStatus: rr.Response.StatusCode, ResponseHeaders: rr.Response.Headers,
		ResponseBody: rr.Response.Body, FetchedViaGETFallback: fetchedViaGET && method == http.MethodPost,
	})

	for _, linkURL := range extractLinkHeaderURLs(rawURL, rr.Response.Headers) {
		c.enqueueCandidate(linkURL, http.MethodGet, depth+1, SourceLinkHeader, 0.75, "Link response header", budget, nil, rawURL)
	}

	if isHTML {
		c.probeSecurityHeaders(ctx, rawURL, method)
	}

	// Scan every response body (HTML, JSON, JS, plain text, …) for leaked
	// secrets — credentials are not limited to .js files.
	c.scanSecrets(rawURL, body)

	isJS := strings.Contains(lowerCT, "javascript") || strings.Contains(lowerCT, "ecmascript") ||
		strings.HasSuffix(strings.ToLower(rawURL), ".js") || strings.HasSuffix(strings.ToLower(rawURL), ".mjs")

	var discovered []DiscoveredEndpoint
	if isHTML {
		discovered = append(discovered, ExtractFromHTML(rawURL, body)...)
		discovered = append(discovered, ExtractManifestAndServiceWorker(rawURL, body)...)
		// Inline <script> blocks frequently contain fetch/axios/XHR calls.
		discovered = append(discovered, ExtractASTFromJSBundle(rawURL, body)...)
	}
	if isJS {
		discovered = append(discovered, ExtractFromJSBundle(rawURL, body)...)
		// AST pass complements the regex pass for multiline/template-literal calls.
		discovered = append(discovered, ExtractASTFromJSBundle(rawURL, body)...)
	}
	if strings.Contains(strings.ToLower(rawURL), "robots.txt") {
		discovered = append(discovered, ExtractFromRobots(rawURL, body)...)
	}
	if strings.Contains(strings.ToLower(rawURL), "sitemap") {
		discovered = append(discovered, ExtractFromSitemap(body)...)
	}

	var browserState *BrowserSnapshot
	if isHTML && c.cfg.EnableHeadlessCrawler && c.browser != nil {
		if instrumented, ok := c.browser.(InstrumentedBrowserFetcher); ok {
			snapshot, browserErr := instrumented.FetchInstrumented(ctx, rawURL)
			if browserErr == nil {
				browserState = &snapshot
				discovered = append(discovered, snapshot.NetworkCalls...)
			}
		} else {
			_, xhr, browserErr := c.browser.Fetch(ctx, rawURL)
			if browserErr == nil {
				discovered = append(discovered, xhr...)
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
		for _, ep := range CommonAPIDocPaths(base) {
			c.enqueueCandidate(ep.URL, ep.Method, 0, ep.Source, ep.Confidence, ep.WhyDiscovered, budget, nil, "")
		}
		c.enqueueCandidate(base+"/robots.txt", http.MethodGet, 0, SourceRobots, 0.9, "well-known robots.txt", budget, nil, "")
		c.enqueueCandidate(base+"/sitemap.xml", http.MethodGet, 0, SourceSitemap, 0.9, "well-known sitemap.xml", budget, nil, "")
	}
}

// CrawlEndpointSeeds enqueues discovered endpoints with their HTTP methods (used for JS API re-crawl).
func (c *Crawler) CrawlEndpointSeeds(ctx context.Context, seeds []DiscoveredEndpoint, budget Budget) error {
	if budget.MaxDepth <= 0 {
		budget.MaxDepth = c.cfg.MaxDepth
		if budget.MaxDepth <= 0 {
			budget.MaxDepth = 4
		}
	}
	for _, ep := range seeds {
		c.enqueueCandidate(ep.URL, ep.Method, 0, ep.Source, ep.Confidence, ep.WhyDiscovered, budget, ep.RequestTemplate, "")
	}
	c.runWorkers(ctx, budget)
	_ = c.flushEndpointEvents()
	return nil
}

func (c *Crawler) enqueueCandidate(rawURL, method string, depth int, source DiscoverySource, confidence float64, why string, budget Budget, tmpl *RequestTemplate, parentURL string) {
	if rawURL == "" || !urlutil.IsPlausibleEndpointURL(rawURL) {
		return
	}
	if method == "" {
		method = "GET"
	}
	if !c.scope.IsInScope(rawURL) || IsCrawlerTrap(rawURL) {
		return
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
	if c.cfg.MaxEndpointsLimit() > 0 && c.discovered >= c.cfg.MaxEndpointsLimit() {
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
	c.recordEndpoint(rawURL, method, source, confidence, depth, why, previewTemplate(rawURL, method, tmpl))
	// Endpoints discovered beyond the configured depth are still recorded for
	// reporting, but we do not crawl them further to respect MaxDepth.
	if budget.MaxDepth > 0 && depth > budget.MaxDepth {
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

	// For non-seeds, only save it when it has been successfully visited (not nil tmpl and not failed status).
	if tmpl == nil && !isSeed {
		return
	}

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

	_ = c.db.SaveDiscoveredEndpoint(c.scanID, ep)

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
	if body == "" {
		return
	}
	content := body
	if len(content) > maxSecretScanBytes {
		content = content[:maxSecretScanBytes]
	}
	for _, m := range secretscan.Detect(content) {
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
		evidence := secretscan.EvidenceJSON(m.Kind, m.Value, sourceURL, m.Line)
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
	if budget.MaxPages > 0 && c.pagesVisited >= budget.MaxPages {
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

func (c *Crawler) reserveRequest(budget Budget) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if budget.RequestBudget > 0 && c.requestsMade >= budget.RequestBudget {
		return false
	}
	if budget.TimeBudget > 0 && time.Since(c.startedAt) >= budget.TimeBudget {
		return false
	}
	c.requestsMade++
	return true
}

func (c *Crawler) Stats() (pages, requests, discovered int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pagesVisited, c.requestsMade, c.discovered
}

// RuntimeCoverage reports unique API and realtime endpoints observed by the
// instrumented browser. This makes authenticated SPA coverage independently
// measurable from static link and JavaScript extraction.
func (c *Crawler) RuntimeCoverage() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.runtimeFound
}

func runtimeDiscoverySource(source DiscoverySource) bool {
	switch source {
	case SourceBrowserXHR, SourceGraphQL, SourceWebSocket, SourceEventSource:
		return true
	default:
		return false
	}
}
