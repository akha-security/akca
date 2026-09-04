package jsanalyzer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/findingevent"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/queue"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/secretscan"
	"github.com/akha-security/akca/engine/internal/storage"
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
}

func New(scanID string, client HTTPDoer, scopeEngine *scope.Engine, db *storage.DB, q *queue.RequestQueue, emit EventSink) *Analyzer {
	return &Analyzer{
		scanID: scanID, client: client, scope: scopeEngine, db: db, queue: q, emit: emit,
		maxBytes: DefaultMaxJSBytes, preview: DefaultPreviewBytes,
	}
}

func (a *Analyzer) AnalyzeContent(jsURL, body string) AnalysisResult {
	content, truncated, previewOnly := PrepareContent(body, a.maxBytes, a.preview)
	ast := ExtractASTLite(content)
	heur := ExtractHeuristic(content)
	merged := DeduplicateSemantic(append(ast, heur...))
	filtered := FilterByConfidence(merged, MinConfidence)

	return AnalysisResult{
		JSURL: jsURL, Truncated: truncated, PreviewOnly: previewOnly, BytesAnalyzed: len(content),
		Endpoints: filtered, Secrets: DetectSecrets(content),
		SourceMaps: DetectSourceMaps(jsURL, content), InternalPaths: DetectInternalPaths(content),
		AnalyzedAt: nowTS(),
	}
}

func (a *Analyzer) DownloadAndAnalyze(ctx context.Context, jsURL string) (AnalysisResult, error) {
	if !a.scope.IsInScope(jsURL) {
		return AnalysisResult{}, nil
	}
	rr, err := a.client.Do(ctx, http.MethodGet, jsURL, nil, nil)
	if err != nil {
		return AnalysisResult{}, err
	}
	if rr.Response.StatusCode == http.StatusNotFound || rr.Response.StatusCode == http.StatusGone {
		return AnalysisResult{}, nil
	}
	result := a.AnalyzeContent(jsURL, rr.Response.Body)
	result.SourceMaps = a.verifySourceMaps(ctx, result.SourceMaps)
	a.publishResult(result)
	return result, nil
}

func (a *Analyzer) Run(ctx context.Context, jsURLs []string) error {
	_ = a.emit("js_analysis_started", "js analysis started", map[string]interface{}{
		"scan_id": a.scanID, "sources": len(jsURLs),
	})
	for _, jsURL := range jsURLs {
		if _, err := a.DownloadAndAnalyze(ctx, jsURL); err != nil {
			_ = a.emit("log", err.Error(), map[string]interface{}{"js_url": jsURL})
		}
	}
	_ = a.emit("js_analysis_finished", "js analysis finished", map[string]interface{}{"scan_id": a.scanID})
	return nil
}

func (a *Analyzer) RunFromStorage(ctx context.Context) error {
	urls, err := a.db.ListScriptEndpoints(a.scanID, 0)
	if err != nil {
		return err
	}
	return a.Run(ctx, urls)
}

func (a *Analyzer) publishResult(result AnalysisResult) {
	_ = a.emit("crawler_js_file_found", result.JSURL, map[string]interface{}{
		"scan_id": a.scanID, "js_url": result.JSURL, "truncated": result.Truncated,
		"preview_only": result.PreviewOnly, "bytes": result.BytesAnalyzed,
		"endpoint_count": len(result.Endpoints),
	})

	for _, ep := range result.Endpoints {
		resolved, _ := resolveReference(result.JSURL, ep.URL)
		if resolved == "" || !a.scope.IsInScope(resolved) {
			continue
		}
		_ = a.db.SaveDiscoveredEndpoint(a.scanID, map[string]interface{}{
			"url": resolved, "method": ep.Method, "normalized_url": resolved,
			"source": "js_analyzer", "confidence": ep.Confidence, "why_discovered": ep.Why,
		})
		a.queue.Enqueue(queue.Item{URL: resolved, Method: ep.Method, Priority: int(ep.Confidence * 100)})
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
		evidence := passiveEvidenceJSON("secret_exposure", "source_map_exposed", sm.URL, sm.FromFile)
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
			"scan_id": a.scanID, "kind": sec.Kind, "redacted": sec.Redacted, "value": sec.Value, "js_url": result.JSURL,
		})
		if !secretscan.IsReportable(secretscan.Match{Kind: sec.Kind, Value: sec.Value, Confidence: sec.Confidence}) {
			continue
		}
		title := "Secret-like string in JavaScript (" + sec.Kind + ")"
		desc := sec.Kind + " pattern detected in JS source: " + sec.Value
		evidence := secretscan.EvidenceJSON(sec.Kind, sec.Value, result.JSURL, sec.LineHint)
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
			evidence := passiveEvidenceJSON("information_disclosure", "internal_path_disclosure", ip.Path, result.JSURL)
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

func passiveEvidenceJSON(module, signal, payload, sourceURL string) string {
	evidence := map[string]interface{}{
		"module":   module,
		"signal":   signal,
		"payload":  map[string]string{"value": payload},
		"location": "javascript_source",
		"request": map[string]interface{}{
			"method": "GET", "url": sourceURL,
		},
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
