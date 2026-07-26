package fuzzing

import (
	"context"
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
}

const (
	prefixMissThreshold    = 3
	maxAdaptiveTasksPerRun = 256
)

func NewEngine(scanID string, client HTTPDoer, scopeEngine *scope.Engine, db *storage.DB, emit EventSink, workers int) *Engine {
	if workers <= 0 {
		workers = 6
	}
	return &Engine{
		scanID: scanID, client: client, scope: scopeEngine, db: db, emit: emit,
		workers: workers, soft404: NewSoft404Calibrator(),
		queue403: NewQueue403(10000), aggregator: NewResultAggregator(scanID, 50, emit),
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
	seen := make(map[string]struct{}, len(tasks)+maxAdaptiveTasksPerRun)
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
	deepTasks = appendNewFuzzTasks(deepTasks, adaptive, seen, maxAdaptiveTasksPerRun)

	// Stage 2: Filter deep tasks and run them
	var filteredDeep []FuzzTask
	for _, t := range deepTasks {
		path := extractPath(t.URL)
		prefix := pathPrefix(path)
		if _, banned := e.bannedPrefixes.Load(prefix); !banned {
			filteredDeep = append(filteredDeep, t)
		}
	}

	var secondGeneration []FuzzTask
	if len(filteredDeep) > 0 {
		secondGeneration = e.runBatch(ctx, filteredDeep)
	}

	// One bounded follow-up generation allows sitemap indexes to reveal child
	// sitemaps and then concrete paths without turning fuzzing into a crawler.
	thirdStage := appendNewFuzzTasks(nil, secondGeneration, seen, maxAdaptiveTasksPerRun-len(adaptive))
	thirdStage = e.filterBannedTasks(thirdStage)
	if len(thirdStage) > 0 {
		e.runBatch(ctx, thirdStage)
	}

	_ = e.aggregator.Flush()
	_ = e.emit("fuzzing_finished", "fuzzing finished", map[string]interface{}{
		"scan_id": e.scanID, "queue_403": e.queue403.Metrics(),
	})
	return nil
}

func (e *Engine) runBatch(ctx context.Context, tasks []FuzzTask) []FuzzTask {
	taskCh := make(chan FuzzTask, len(tasks))
	for _, t := range tasks {
		taskCh <- t
	}
	close(taskCh)

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
				newTasks := e.fuzzOne(ctx, task)
				if len(newTasks) > 0 {
					discoveredMu.Lock()
					discovered = append(discovered, newTasks...)
					discoveredMu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	return dedupeFuzzTasks(discovered)
}

func (e *Engine) fuzzOne(ctx context.Context, task FuzzTask) []FuzzTask {
	if !e.scope.IsInScope(task.URL) {
		return nil
	}
	path := extractPath(task.URL)
	prefix := pathPrefix(path)
	if _, banned := e.bannedPrefixes.Load(prefix); banned {
		return nil
	}

	rr, err := e.client.Do(ctx, task.Method, task.URL, nil, nil)
	if err != nil {
		return nil
	}

	host := hostFromURL(task.URL)
	body := rr.Response.Body
	status := rr.Response.StatusCode
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
		e.recordPrefixMiss(prefix)
	}

	signal := ClassifySignal(status, isSoft404, isArchive)

	result := FuzzResult{
		URL: task.URL, Method: task.Method, StatusCode: status,
		Category: string(task.Category), Signal: signal,
		BodyLength: len(body), IsSoft404: isSoft404, IsArchive: isArchive,
	}

	_ = e.db.SaveFuzzResult(e.scanID, result)
	_ = e.aggregator.Add(result)

	if status == http.StatusForbidden {
		e.queue403.Enqueue(task.URL, task.Method)
		_ = e.emit("four_oh_three_observed", "403 observed", map[string]interface{}{
			"scan_id": e.scanID, "url": task.URL, "method": task.Method,
			"queue": e.queue403.Metrics(),
		})
	}
	if status == http.StatusUnauthorized {
		e.queue403.Enqueue(task.URL, task.Method)
		_ = e.emit("four_oh_one_observed", "401 observed", map[string]interface{}{
			"scan_id": e.scanID, "url": task.URL, "method": task.Method,
			"queue": e.queue403.Metrics(),
		})
	}
	if isArchive {
		_ = e.emit("archive_exposure_detected", task.URL, map[string]interface{}{
			"scan_id": e.scanID, "url": task.URL, "status": status,
		})
	}
	if !isSoft404 {
		return DiscoverTasks(task, status, body, contentType)
	}
	return nil
}

func extractPath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err == nil && u.Path != "" {
		return u.Path
	}
	return "/"
}

func pathPrefix(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		return "/"
	}
	return "/" + parts[0]
}

func (e *Engine) recordPrefixMiss(prefix string) {
	value, _ := e.prefixMisses.LoadOrStore(prefix, &atomic.Int32{})
	if value.(*atomic.Int32).Add(1) >= prefixMissThreshold {
		e.bannedPrefixes.Store(prefix, struct{}{})
	}
}

func (e *Engine) filterBannedTasks(tasks []FuzzTask) []FuzzTask {
	out := make([]FuzzTask, 0, len(tasks))
	for _, task := range tasks {
		if _, banned := e.bannedPrefixes.Load(pathPrefix(extractPath(task.URL))); !banned {
			out = append(out, task)
		}
	}
	return out
}

func appendNewFuzzTasks(dst, candidates []FuzzTask, seen map[string]struct{}, limit int) []FuzzTask {
	if limit <= 0 {
		return dst
	}
	added := 0
	for _, task := range candidates {
		key := fuzzTaskKey(task)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		dst = append(dst, task)
		added++
		if added >= limit {
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
