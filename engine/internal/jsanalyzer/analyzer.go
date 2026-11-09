package jsanalyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/akha-security/akca/engine/internal/crawler"
	"github.com/akha-security/akca/engine/internal/findingevent"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/queue"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/secretscan"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/urlutil"
)

type HTTPDoer interface {
	Do(ctx context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error)
}

type Analyzer struct {
	scanID   string
	client   HTTPDoer
	scope    *scope.Engine
	db       *storage.DB
	queue    *queue.RequestQueue
	emit     EventSink
	maxBytes int
	preview  int
	workers  int
}

func New(scanID string, client HTTPDoer, scopeEngine *scope.Engine, db *storage.DB, q *queue.RequestQueue, emit EventSink) *Analyzer {
	if emit == nil {
		emit = func(string, string, map[string]interface{}) error { return nil }
	}
	return &Analyzer{
		scanID: scanID, client: client, scope: scopeEngine, db: db, queue: q, emit: emit,
		maxBytes: DefaultMaxJSBytes, preview: DefaultPreviewBytes, workers: 4,
	}
}

func (a *Analyzer) SetConcurrency(workers int) {
	if workers > 0 {
		a.workers = min(workers, 8)
	}
}

func (a *Analyzer) AnalyzeContent(jsURL, body string) AnalysisResult {
	content, truncated, previewOnly := PrepareContent(body, a.maxBytes, a.preview)
	ast := ExtractASTLite(content)
	heur := ExtractHeuristic(content)
	// Reuse the call-expression parser so fetch options and axios request
	// bodies survive discovery instead of being guessed from adjacent words.
	var extracted []ExtractedEndpoint
	callURLs := map[string]bool{}
	for _, ep := range crawler.ExtractASTFromJSBundle(jsURL, content) {
		callURLs[ep.URL] = true
		item := ExtractedEndpoint{URL: ep.URL, Method: ep.Method, Source: "call_expression",
			Extraction: "ast", Confidence: ep.Confidence, Why: ep.WhyDiscovered}
		if strings.HasPrefix(ep.WhyDiscovered, "dynamic import") {
			item.Source = "dynamic_import"
		}
		if ep.RequestTemplate != nil {
			t := ep.RequestTemplate
			item.RequestTemplate = &storage.DiscoveryRequestTemplate{
				Method: ep.Method, URL: ep.URL, Headers: t.Headers, Body: t.Body, ContentType: t.ContentType,
			}
		}
		extracted = append(extracted, item)
	}
	for _, ep := range append(ast, heur...) {
		resolved, _ := resolveReference(jsURL, ep.URL)
		if !callURLs[resolved] {
			extracted = append(extracted, ep)
		}
	}
	merged := DeduplicateSemantic(extracted)
	filtered := make([]ExtractedEndpoint, 0, len(merged))
	for _, endpoint := range merged {
		// Script dependencies are navigation inputs, not vulnerability signals.
		// Retain them even when their generic API confidence is below the
		// reporting threshold so lazy-loaded SPA chunks can be analyzed.
		if endpoint.Confidence >= MinConfidence || javascriptDependency(endpoint) {
			filtered = append(filtered, endpoint)
		}
	}

	return AnalysisResult{
		SourceContent: content, JSURL: jsURL, Truncated: truncated, PreviewOnly: previewOnly, BytesAnalyzed: len(content),
		Endpoints: filtered, Secrets: DetectSecrets(content),
		SourceMaps: DetectSourceMaps(jsURL, content), InternalPaths: DetectInternalPaths(content),
		AnalyzedAt: nowTS(),
	}
}

func (a *Analyzer) DownloadAndAnalyze(ctx context.Context, jsURL string) (AnalysisResult, error) {
	result, err := a.downloadAndAnalyze(ctx, jsURL)
	if err == nil && result.JSURL != "" {
		err = a.publishResult(result)
	}
	return result, err
}

func (a *Analyzer) downloadAndAnalyze(ctx context.Context, jsURL string) (AnalysisResult, error) {
	if !a.scope.IsInScope(jsURL) {
		return AnalysisResult{}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	rr, err := a.client.Do(ctx, http.MethodGet, jsURL, nil, nil)
	if err != nil {
		return AnalysisResult{}, err
	}
	if rr.Response.StatusCode < 200 || rr.Response.StatusCode >= 300 {
		return AnalysisResult{}, nil
	}
	for key, value := range rr.Response.Headers {
		if strings.EqualFold(key, "Content-Type") && strings.Contains(strings.ToLower(value), "html") {
			return AnalysisResult{}, nil
		}
	}
	result := a.AnalyzeContent(jsURL, rr.Response.Body)
	result.SourceMaps = a.verifySourceMaps(ctx, result.SourceMaps)
	return result, nil
}

func (a *Analyzer) Run(ctx context.Context, jsURLs []string) error {
	_ = a.emit("js_analysis_started", "js analysis started", map[string]interface{}{
		"scan_id": a.scanID, "sources": len(jsURLs),
	})
	const maxRecursiveScripts = 2000
	var pending []string
	scheduled := make(map[string]struct{})
	limitReached := false
	schedule := func(rawURL string) {
		u, err := url.Parse(rawURL)
		if err != nil {
			return
		}
		u.Fragment = ""
		jsURL := u.String()
		if !urlutil.IsPlausibleEndpointURL(jsURL) || urlutil.HasPathTemplate(jsURL) || !a.scope.IsInScope(jsURL) {
			return
		}
		if _, duplicate := scheduled[jsURL]; duplicate {
			return
		}
		if len(scheduled) >= maxRecursiveScripts {
			limitReached = true
			return
		}
		scheduled[jsURL] = struct{}{}
		pending = append(pending, jsURL)
	}
	for _, jsURL := range jsURLs {
		schedule(jsURL)
	}
	workers := a.workers
	if workers <= 0 {
		workers = 4
	}
	analyzed, attempted, failures := 0, 0, 0
	for len(pending) > 0 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		batch := pending[:min(workers, len(pending))]
		pending = pending[len(batch):]
		type outcome struct {
			result AnalysisResult
			err    error
		}
		results := make([]outcome, len(batch))
		var wg sync.WaitGroup
		for i, jsURL := range batch {
			wg.Add(1)
			go func() {
				defer wg.Done()
				results[i].result, results[i].err = a.downloadAndAnalyze(ctx, jsURL)
			}()
		}
		wg.Wait()
		// Persist and publish on one goroutine. Event sinks and request template
		// merging retain their ordering while network downloads run concurrently.
		for i, item := range results {
			attempted++
			if item.err == nil && item.result.JSURL != "" {
				analyzed++
				item.err = a.publishResult(item.result)
			}
			if item.err != nil {
				failures++
				_ = a.emit("log", item.err.Error(), map[string]interface{}{"js_url": batch[i]})
				continue
			}
			for _, endpoint := range item.result.Endpoints {
				if javascriptDependency(endpoint) {
					resolved, err := resolveReference(batch[i], endpoint.URL)
					if err == nil {
						schedule(resolved)
					}
				}
			}
		}
		_ = a.emit("js_analysis_progress", "JavaScript analysis progress", map[string]interface{}{
			"scan_id": a.scanID, "completed": attempted, "analyzed_sources": analyzed,
			"queued_sources": len(pending), "discovered_sources": len(scheduled), "failed_sources": failures,
		})
	}
	if limitReached {
		_ = a.emit("coverage_gap", "JavaScript dependency analysis reached its safety ceiling", map[string]interface{}{
			"phase": "js_analysis", "analyzed": analyzed, "limit": maxRecursiveScripts, "reason": "js_dependency_limit",
		})
	}
	_ = a.emit("js_analysis_finished", "js analysis finished", map[string]interface{}{
		"scan_id": a.scanID, "analyzed_sources": analyzed, "discovered_dependencies": len(scheduled), "failed_sources": failures,
	})
	if failures > 0 || limitReached {
		return fmt.Errorf("JavaScript analysis incomplete: %d failed sources (dependency limit reached: %t)", failures, limitReached)
	}
	return nil
}

func javascriptDependency(endpoint ExtractedEndpoint) bool {
	lowerURL := strings.ToLower(strings.SplitN(endpoint.URL, "?", 2)[0])
	if strings.HasSuffix(lowerURL, ".js") || strings.HasSuffix(lowerURL, ".mjs") || strings.HasSuffix(lowerURL, ".cjs") {
		return true
	}
	switch endpoint.Source {
	case "dynamic_import", "chunk", "vite_asset", "service_worker":
		return true
	default:
		return false
	}
}

func (a *Analyzer) RunFromStorage(ctx context.Context) error {
	urls, err := a.db.ListScriptEndpoints(a.scanID, 0)
	if err != nil {
		return err
	}
	return a.Run(ctx, urls)
}

func (a *Analyzer) publishResult(result AnalysisResult) error {
	_ = a.emit("crawler_js_file_found", result.JSURL, map[string]interface{}{
		"scan_id": a.scanID, "js_url": result.JSURL, "truncated": result.Truncated,
		"preview_only": result.PreviewOnly, "bytes": result.BytesAnalyzed,
		"endpoint_count": len(result.Endpoints),
	})

	for _, ep := range result.Endpoints {
		resolved, _ := resolveReference(result.JSURL, ep.URL)
		if !urlutil.IsPlausibleEndpointURL(resolved) || !a.scope.IsInScope(resolved) {
			continue
		}
		if err := a.db.SaveDiscoveredEndpoint(a.scanID, map[string]interface{}{
			"url": resolved, "method": ep.Method, "normalized_url": resolved,
			"source": "js_analyzer", "confidence": ep.Confidence, "why_discovered": ep.Why,
			"request_template": ep.RequestTemplate,
		}); err != nil {
			return err
		}
		if a.queue != nil {
			a.queue.Enqueue(queue.Item{URL: resolved, Method: ep.Method, Priority: int(ep.Confidence * 100)})
		}
	}

	if len(result.Endpoints) > 0 {
		_ = a.emit("endpoint_discovered", "js endpoints", map[string]interface{}{
			"scan_id": a.scanID, "js_url": result.JSURL, "count": len(result.Endpoints),
		})
	}

	for _, sm := range result.SourceMaps {
		if !sm.Exposed {
			continue
		}
		_ = a.emit("source_map_exposed", sm.URL, map[string]interface{}{
			"scan_id": a.scanID, "from_file": sm.FromFile, "map_url": sm.URL,
		})
		title := "Exposed JavaScript Source Map"
		evidence := passiveEvidenceJSON("secret_exposure", "source_map_exposed", sm.URL, sm.FromFile, result.SourceContent)
		findingID, err := a.db.SaveFinding(a.scanID, title, "info", "secret_exposure",
			"Source map reference found in JavaScript: "+sm.URL, sm.FromFile, "", 0.9, evidence)
		if err == nil {
			_ = a.emit("finding_detected", title, findingevent.Payload(findingevent.Data{
				FindingID: findingID, ScanID: a.scanID, Title: title, Severity: "info",
				VulnClass: "secret_exposure", Endpoint: sm.FromFile, Location: "javascript_source",
				Method: "GET", Payload: sm.URL, Signal: "source_map_exposed", Score: 0.9,
				Passive: true,
			}))
		}
	}

	for _, sec := range result.Secrets {
		_ = a.emit("js_secret_detected", sec.Kind, map[string]interface{}{
			"scan_id": a.scanID, "kind": sec.Kind, "redacted": sec.Redacted, "js_url": result.JSURL,
		})
		if !secretscan.IsReportable(secretscan.Match{Kind: sec.Kind, Value: sec.Value, Confidence: sec.Confidence}) {
			continue
		}
		title := "Secret-like string in JavaScript (" + sec.Kind + ")"
		desc := sec.Kind + " pattern detected in JS source: " + sec.Value
		evidence := secretscan.EvidenceJSONWithResponse(sec.Kind, sec.Value, result.JSURL, sec.LineHint, result.SourceContent)
		severity := secretscan.Severity(sec.Confidence)
		findingID, err := a.db.SaveFinding(a.scanID, title, severity, "secret_exposure",
			desc, result.JSURL, "", sec.Confidence, evidence)
		if err == nil {
			_ = a.emit("finding_detected", title, findingevent.Payload(findingevent.Data{
				FindingID: findingID, ScanID: a.scanID, Title: title, Severity: severity,
				VulnClass: "secret_exposure", Endpoint: result.JSURL, Location: "javascript_source",
				Method: "GET", Payload: sec.Value, Signal: "passive_secret", Score: sec.Confidence,
				Passive: true,
			}))
		}
	}

	for _, ip := range result.InternalPaths {
		_ = a.emit("js_internal_path_found", ip.Path, map[string]interface{}{
			"scan_id": a.scanID, "kind": ip.Kind, "path": ip.Path, "js_url": result.JSURL,
		})
		// Only relative/internal references are interesting for disclosure;
		// third-party package imports are skipped to avoid noise.
		if ip.Kind == "internal" {
			title := "Internal path reference in JavaScript"
			evidence := passiveEvidenceJSON("information_disclosure", "internal_path_disclosure", ip.Path, result.JSURL, result.SourceContent)
			findingID, err := a.db.SaveFinding(a.scanID, title, "info", "information_disclosure",
				"Internal path/module reference found in JS: "+ip.Path, result.JSURL, "", ip.Confidence, evidence)
			if err == nil {
				_ = a.emit("finding_detected", title, findingevent.Payload(findingevent.Data{
					FindingID: findingID, ScanID: a.scanID, Title: title, Severity: "info",
					VulnClass: "information_disclosure", Endpoint: result.JSURL, Location: "javascript_source",
					Method: "GET", Payload: ip.Path, Signal: "internal_path_disclosure", Score: ip.Confidence,
					Passive: true,
				}))
			}
		}
	}
	return nil
}

func (a *Analyzer) verifySourceMaps(ctx context.Context, refs []SourceMapRef) []SourceMapRef {
	verified := make([]SourceMapRef, 0, len(refs))
	for _, ref := range refs {
		resolved, err := resolveReference(ref.FromFile, ref.URL)
		if err != nil || resolved == "" || !a.scope.IsInScope(resolved) {
			continue
		}
		rr, err := a.client.Do(ctx, http.MethodGet, resolved, nil, nil)
		if err != nil || rr.Response.StatusCode != http.StatusOK {
			continue
		}
		var document struct {
			Version        int               `json:"version"`
			Sources        []string          `json:"sources"`
			SourcesContent []json.RawMessage `json:"sourcesContent"`
		}
		if json.Unmarshal([]byte(rr.Response.Body), &document) != nil || document.Version <= 0 ||
			(len(document.Sources) == 0 && len(document.SourcesContent) == 0) {
			continue
		}
		ref.URL = resolved
		ref.Exposed = true
		ref.Confidence = 0.98
		verified = append(verified, ref)
	}
	return verified
}

func passiveEvidenceJSON(module, signal, payload, sourceURL string, responseBody ...string) string {
	evidence := map[string]interface{}{
		"module":   module,
		"signal":   signal,
		"payload":  map[string]string{"value": payload},
		"location": "javascript_source",
		"request": map[string]interface{}{
			"method": "GET", "url": sourceURL,
		},
	}
	if len(responseBody) > 0 {
		if excerpt := secretscan.ResponseSnippet(responseBody[0], payload); excerpt != "" {
			evidence["resp_body"] = excerpt
			evidence["response_markers"] = []string{payload}
		}
	}
	raw, _ := json.Marshal(evidence)
	return string(raw)
}

func resolveReference(baseURL, ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", nil
	}
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return ref, nil
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	rel, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(rel).String(), nil
}
