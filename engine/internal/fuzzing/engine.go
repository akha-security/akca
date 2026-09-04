package fuzzing

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
)

type Engine struct {
	scanID         string
	client         HTTPDoer
	scope          *scope.Engine
	db             *storage.DB
	emit           EventSink
	workers        int
	soft404        *Soft404Calibrator
	queue403       *Queue403
	aggregator     *ResultAggregator
	bannedPrefixes sync.Map
	prefixMisses   sync.Map
	probed         atomic.Int64
	reachable      atomic.Int64
	authRestricted atomic.Int64
	archives       atomic.Int64
	failures       atomic.Int64
}

const prefixMissThreshold = 3

func NewEngine(scanID string, client HTTPDoer, scopeEngine *scope.Engine, db *storage.DB, emit EventSink, workers int) *Engine {
	if workers <= 0 {
		workers = 6
	}
	return &Engine{
		scanID: scanID, client: client, scope: scopeEngine, db: db, emit: emit,
		workers: workers, soft404: NewSoft404Calibrator(),
		queue403: NewQueue403(0), aggregator: NewResultAggregator(scanID, 50, emit),
	}
}

func (e *Engine) Queue403() *Queue403 {
	return e.queue403
}

func (e *Engine) Run(ctx context.Context, baseURLs []string) error {
	for _, base := range baseURLs {
		e.soft404.Calibrate(ctx, e.client, base)
	}
	var tasks []FuzzTask
	for _, base := range baseURLs {
		tasks = append(tasks, BuildTasks(base)...)
	}
	return e.RunTasks(ctx, tasks)
}

func (e *Engine) RunWithHints(ctx context.Context, baseURLs []string, hintsByHost map[string][]string) error {
	for _, base := range baseURLs {
		e.soft404.Calibrate(ctx, e.client, base)
	}
	var tasks []FuzzTask
	for _, base := range baseURLs {
		hints := hintsByHost[hostFromURL(base)]
		tasks = append(tasks, BuildTasksForTech(base, hints)...)
	}
	return e.RunTasks(ctx, tasks)
}

func (e *Engine) RunTasks(ctx context.Context, tasks []FuzzTask) error {
	_ = e.emit("fuzzing_started", "fuzzing started", map[string]interface{}{"scan_id": e.scanID})
	_ = e.db.EnsureScan(e.scanID)
	tasks = dedupeFuzzTasks(tasks)
	seen := make(map[string]struct{}, len(tasks))
	for _, task := range tasks {
		seen[fuzzTaskKey(task)] = struct{}{}
	}

	// Stage 1: Run root paths first (e.g. /admin, /api, /actuator)
	var rootTasks []FuzzTask
	var deepTasks []FuzzTask
	for _, t := range tasks {
		path := extractPath(t.URL)
		if strings.Count(strings.Trim(path, "/"), "/") < 1 {
			rootTasks = append(rootTasks, t)
		} else {
			deepTasks = append(deepTasks, t)
		}
	}

	var adaptive []FuzzTask
	if len(rootTasks) > 0 {
		adaptive = e.runBatch(ctx, rootTasks)
	}
	deepTasks = appendNewFuzzTasks(deepTasks, adaptive, seen, 0)

	// Stage 2: Filter deep tasks and run them
	var filteredDeep []FuzzTask
	for _, t := range deepTasks {
		path := extractPath(t.URL)
		prefix := pathPrefix(path)
		if prefix != "" {
			if _, banned := e.bannedPrefixes.Load(prefix); banned {
				continue
			}
		}
		filteredDeep = append(filteredDeep, t)
	}

	var secondGeneration []FuzzTask
	if len(filteredDeep) > 0 {
		secondGeneration = e.runBatch(ctx, filteredDeep)
	}

	// One bounded follow-up generation allows sitemap indexes to reveal child
	// sitemaps and then concrete paths without turning fuzzing into a crawler.
	thirdStage := appendNewFuzzTasks(nil, secondGeneration, seen, 0)
	thirdStage = e.filterBannedTasks(thirdStage)
	if len(thirdStage) > 0 {
		e.runBatch(ctx, thirdStage)
	}

	if err := e.aggregator.Flush(); err != nil {
		e.failures.Add(1)
		_ = e.emit("scan_error", "fuzz result event flush failed: "+err.Error(), map[string]interface{}{
			"scan_id": e.scanID, "phase": "fuzzing",
		})
	}
	_ = e.emit("fuzzing_finished", "fuzzing finished", map[string]interface{}{
		"scan_id": e.scanID, "queue_403": e.queue403.Metrics(),
	})
	_ = e.emit("fuzzing_discovery_summary", "directory and path fuzzing summary", map[string]interface{}{
		"scan_id": e.scanID,
		"probed":  e.probed.Load(),
		"live":    e.reachable.Load(),
		"blocked": e.authRestricted.Load(),
		"archive": e.archives.Load(),
	})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if failed := e.failures.Load(); failed > 0 {
		_ = e.emit("log", fmt.Sprintf("fuzzing completed with %d network/request errors out of %d probes", failed, e.probed.Load()), map[string]interface{}{
			"scan_id": e.scanID, "phase": "fuzzing", "failures": failed, "probed": e.probed.Load(),
		})
	}
	return nil
}

func (e *Engine) runBatch(ctx context.Context, tasks []FuzzTask) []FuzzTask {
	queueSize := e.workers * 2
	if queueSize < 1 {
		queueSize = 1
	}
	if queueSize > 256 {
		queueSize = 256
	}
	taskCh := make(chan FuzzTask, queueSize)

	var wg sync.WaitGroup
	var discoveredMu sync.Mutex
	var discovered []FuzzTask
	for i := 0; i < e.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range taskCh {
				if ctx.Err() != nil {
					return
				}
				var newTasks []FuzzTask
				func() {
					defer func() {
						if recovered := recover(); recovered != nil {
							e.failures.Add(1)
							_ = e.emit("log", fmt.Sprintf("fuzzing task recovered from panic: %v", recovered), map[string]interface{}{
								"scan_id": e.scanID, "url": task.URL,
							})
						}
					}()
					newTasks = e.fuzzOne(ctx, task)
				}()
				if len(newTasks) > 0 {
					discoveredMu.Lock()
					discovered = append(discovered, newTasks...)
					discoveredMu.Unlock()
				}
			}
		}()
	}
feedLoop:
	for _, task := range tasks {
		select {
		case taskCh <- task:
		case <-ctx.Done():
			break feedLoop
		}
	}
	close(taskCh)
	wg.Wait()
	return dedupeFuzzTasks(discovered)
}

func (e *Engine) fuzzOne(ctx context.Context, task FuzzTask) []FuzzTask {
	if !e.scope.IsInScope(task.URL) {
		return nil
	}
	path := extractPath(task.URL)
	prefix := pathPrefix(path)
	if prefix != "" {
		if _, banned := e.bannedPrefixes.Load(prefix); banned {
			return nil
		}
	}

	rr, err := e.client.Do(ctx, task.Method, task.URL, nil, nil)
	if err != nil {
		e.failures.Add(1)
		_ = e.emit("log", "fuzzing request failed: "+err.Error(), map[string]interface{}{
			"scan_id": e.scanID, "url": task.URL, "method": task.Method,
		})
		return nil
	}

	host := hostFromURL(task.URL)
	body := rr.Response.Body
	status := rr.Response.StatusCode
	e.probed.Add(1)
	contentType := ""
	for k, v := range rr.Response.Headers {
		if strings.EqualFold(k, "Content-Type") {
			contentType = v
			break
		}
	}

	isSoft404 := e.soft404.IsSoft404(host, status, body)
	isArchive := IsArchiveExposure(task.URL, status, contentType)

	if (status == http.StatusNotFound || status == http.StatusGone) && !isSoft404 {
		if prefix != "" {
			e.recordPrefixMiss(prefix)
		}
	}

	signal := ClassifySignal(status, isSoft404, isArchive)

	result := FuzzResult{
		URL: task.URL, Method: task.Method, StatusCode: status,
		Category: string(task.Category), Signal: signal,
		BodyLength: len(body), IsSoft404: isSoft404, IsArchive: isArchive,
	}

	if err := e.db.SaveFuzzResult(e.scanID, result); err != nil {
		e.failures.Add(1)
		_ = e.emit("scan_error", "fuzz result could not be persisted: "+err.Error(), map[string]interface{}{
			"scan_id": e.scanID, "phase": "fuzzing", "url": task.URL,
		})
	}
	if err := e.aggregator.Add(result); err != nil {
		e.failures.Add(1)
	}
	if shouldPromoteFuzzResult(status, isSoft404) {
		e.reachable.Add(1)
		if err := e.db.SaveDiscoveredEndpoint(e.scanID, map[string]interface{}{
			"url":              task.URL,
			"method":           strings.ToUpper(strings.TrimSpace(task.Method)),
			"normalized_url":   task.URL,
			"source":           "path_fuzzing",
			"confidence":       fuzzDiscoveryConfidence(status, isArchive),
			"why_discovered":   fmt.Sprintf("Directory & Path Fuzzing returned HTTP %d (%s)", status, signal),
			"status_code":      status,
			"category":         string(task.Category),
			"signal":           signal,
			"content_type":     contentType,
			"body_length":      len(body),
			"is_archive":       isArchive,
			"request_template": map[string]interface{}{"method": task.Method, "url": task.URL},
		}); err != nil {
			e.failures.Add(1)
			_ = e.emit("scan_error", "fuzz-discovered endpoint could not be persisted: "+err.Error(), map[string]interface{}{
				"scan_id": e.scanID, "phase": "fuzzing", "url": task.URL,
			})
		}
	}

	if status == http.StatusForbidden {
		e.authRestricted.Add(1)
		e.queue403.Enqueue(task.URL, task.Method)
		_ = e.emit("four_oh_three_observed", "403 observed", map[string]interface{}{
			"scan_id": e.scanID, "url": task.URL, "method": task.Method,
			"queue": e.queue403.Metrics(),
		})
	}
	if status == http.StatusUnauthorized {
		e.authRestricted.Add(1)
		e.queue403.Enqueue(task.URL, task.Method)
		_ = e.emit("four_oh_one_observed", "401 observed", map[string]interface{}{
			"scan_id": e.scanID, "url": task.URL, "method": task.Method,
			"queue": e.queue403.Metrics(),
		})
	}
	if isArchive {
		e.archives.Add(1)
		_ = e.emit("archive_exposure_detected", task.URL, map[string]interface{}{
			"scan_id": e.scanID, "url": task.URL, "status": status,
		})
	}
	if !isSoft404 {
		return DiscoverTasks(task, status, body, contentType)
	}
	return nil
}

func shouldPromoteFuzzResult(status int, soft404 bool) bool {
	if soft404 || status == http.StatusNotFound || status == http.StatusGone || status <= 0 {
		return false
	}
	// Don't promote gateway/server error noise (502, 503, 504) or rate limits (429)
	if status == http.StatusBadGateway || status == http.StatusServiceUnavailable ||
		status == http.StatusGatewayTimeout || status == http.StatusTooManyRequests {
		return false
	}
	// 2xx, 3xx, 401, 403, 405, 422 are genuine signals that a resource/handler exists
	if (status >= 200 && status < 400) ||
		status == http.StatusUnauthorized ||
		status == http.StatusForbidden ||
		status == http.StatusMethodNotAllowed ||
		status == http.StatusUnprocessableEntity {
		return true
	}
	return status == http.StatusInternalServerError
}

func fuzzDiscoveryConfidence(status int, archive bool) float64 {
	switch {
	case archive:
		return 0.95
	case status >= 200 && status < 300:
		return 0.90
	case status == http.StatusForbidden || status == http.StatusUnauthorized:
		return 0.80
	case status == http.StatusMethodNotAllowed || status == http.StatusUnprocessableEntity:
		return 0.75
	case status >= 300 && status < 400:
		return 0.70
	case status == http.StatusInternalServerError:
		return 0.50
	default:
		return 0.40
	}
}

func extractPath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err == nil && u.Path != "" {
		return u.Path
	}
	return "/"
}

var protectedRootPrefixes = map[string]bool{
	"api":      true,
	"v1":       true,
	"v2":       true,
	"v3":       true,
	"rest":     true,
	"graphql":  true,
	"actuator": true,
	"app":      true,
}

func pathPrefix(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		return "/"
	}
	first := strings.ToLower(parts[0])
	if protectedRootPrefixes[first] {
		// Protected roots are never banned at depth 1.
		// Track at depth 2 if available (e.g. /api/deprecated).
		if len(parts) >= 2 && parts[1] != "" {
			return "/" + parts[0] + "/" + parts[1]
		}
		// Return empty to indicate unbannable root prefix.
		return ""
	}
	if len(parts) >= 2 && parts[1] != "" {
		return "/" + parts[0] + "/" + parts[1]
	}
	return "/" + parts[0]
}

func (e *Engine) recordPrefixMiss(prefix string) {
	if prefix == "" || prefix == "/" {
		return
	}
	value, _ := e.prefixMisses.LoadOrStore(prefix, &atomic.Int32{})
	if value.(*atomic.Int32).Add(1) >= prefixMissThreshold {
		e.bannedPrefixes.Store(prefix, struct{}{})
	}
}

func (e *Engine) filterBannedTasks(tasks []FuzzTask) []FuzzTask {
	out := make([]FuzzTask, 0, len(tasks))
	for _, task := range tasks {
		prefix := pathPrefix(extractPath(task.URL))
		if prefix != "" {
			if _, banned := e.bannedPrefixes.Load(prefix); banned {
				continue
			}
		}
		out = append(out, task)
	}
	return out
}

func appendNewFuzzTasks(dst, candidates []FuzzTask, seen map[string]struct{}, limit int) []FuzzTask {
	added := 0
	for _, task := range candidates {
		key := fuzzTaskKey(task)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		dst = append(dst, task)
		added++
		if limit > 0 && added >= limit {
			break
		}
	}
	return dst
}

func dedupeFuzzTasks(tasks []FuzzTask) []FuzzTask {
	seen := make(map[string]struct{}, len(tasks))
	out := make([]FuzzTask, 0, len(tasks))
	for _, task := range tasks {
		key := fuzzTaskKey(task)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, task)
	}
	return out
}

func fuzzTaskKey(task FuzzTask) string {
	return strings.ToUpper(strings.TrimSpace(task.Method)) + " " + task.URL
}
