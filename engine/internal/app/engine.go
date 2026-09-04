package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/distributed"
	"github.com/akha-security/akca/engine/internal/events"
	"github.com/akha-security/akca/engine/internal/fuzzing"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/modules"
	"github.com/akha-security/akca/engine/internal/oast"
	"github.com/akha-security/akca/engine/internal/queue"
	"github.com/akha-security/akca/engine/internal/ratelimit"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/session"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/verification"
	"github.com/akha-security/akca/engine/internal/wafintel"
)

type Engine struct {
	mu            sync.Mutex
	activeScanID  atomic.Pointer[string]
	writer        events.Writer
	batcher       *events.Batcher
	db            *storage.DB
	session       *session.ScanSession
	scope         *scope.Engine
	limiter       *ratelimit.Limiter
	client        *httpclient.Client
	reqQueue      *queue.RequestQueue
	queue403      *fuzzing.Queue403
	oast          *oast.Listener
	verifier      *verification.Engine
	platform      *Platform
	stopCh        chan struct{}
	oastCtx       context.Context
	oastCancel    context.CancelFunc
	scanning      bool
	scanCancel    context.CancelFunc
	scanDone      chan struct{}
	scanErr       error
	metricsCancel context.CancelFunc
	jobs          *distributed.Coordinator
	moduleRunner  *modules.Runner
	closeOnce     sync.Once
	closeErr      error
}

func New(writer events.Writer) (*Engine, error) {
	dbPath, err := storage.DefaultDBPath()
	if err != nil {
		return nil, err
	}
	db, err := storage.Open(dbPath)
	if err != nil {
		return nil, err
	}
	if err := db.Migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}

	cfg := config.DefaultScanConfig()
	cfg.ScanID = fmt.Sprintf("scan-%d", time.Now().Unix())
	scopeEngine := scope.NewEngine(cfg)
	limiter := ratelimit.New(cfg.GlobalRateLimit, cfg.PerHostRateLimit)
	client, err := httpclient.New(cfg, scopeEngine, limiter)
	if err != nil {
		_ = db.Close()
		return nil, err
	}

	batcher := events.NewBatcher(writer, 100, 250*time.Millisecond)
	oastCtx, oastCancel := context.WithCancel(context.Background())
	engine := &Engine{
		writer:     writer,
		batcher:    batcher,
		db:         db,
		session:    session.NewScanSession(cfg),
		scope:      scopeEngine,
		limiter:    limiter,
		client:     client,
		reqQueue:   queue.NewRequestQueue(),
		stopCh:     make(chan struct{}),
		oastCtx:    oastCtx,
		oastCancel: oastCancel,
		jobs:       distributed.NewCoordinator(db, 30*time.Second),
	}
	engine.verifier = verification.NewEngine(db, engine.Emit)
	return engine, nil
}

func (e *Engine) Close() error {
	e.closeOnce.Do(func() {
		e.mu.Lock()
		if e.scanning && e.scanCancel != nil {
			e.scanCancel()
		}
		if e.metricsCancel != nil {
			e.metricsCancel()
		}
		doneCh := e.scanDone
		e.mu.Unlock()

		if doneCh != nil {
			// Every scan operation must observe the scan context. Do not tear the
			// database and event writer out from under a still-running pipeline.
			<-doneCh
		}

		e.shutdownPlatform()
		if e.oast != nil {
			e.oast.Stop()
		}
		if e.oastCancel != nil {
			e.oastCancel()
		}
		if e.stopCh != nil {
			select {
			case <-e.stopCh:
			default:
				close(e.stopCh)
			}
		}
		_ = e.batcher.Close()
		e.closeErr = e.db.Close()
	})
	return e.closeErr
}

func (e *Engine) Emit(eventType, message string, payload map[string]interface{}) error {
	// Persist high-diagnostic-value events to the timeline_events table so
	// skip reasons and error context survive after the scan completes.
	if storage.IsDiagnosticEvent(eventType) && e.db != nil {
		scanID := ""
		if payload != nil {
			if s, ok := payload["scan_id"].(string); ok {
				scanID = s
			}
		}
		if scanID == "" {
			if ptr := e.activeScanID.Load(); ptr != nil {
				scanID = *ptr
			}
		}
		if scanID != "" {
			eventJSON, _ := json.Marshal(payload)
			_ = e.db.SaveTimelineEvent(scanID, eventType, message, string(eventJSON))
		}
	}
	return e.batcher.Emit(events.Event{
		Type:    eventType,
		TS:      time.Now().UTC().Format(time.RFC3339),
		Message: message,
		Payload: payload,
	})
}

var errScanRunning = fmt.Errorf("a scan is already running")

func (e *Engine) StartScan(cfg config.ScanConfig) error {
	return e.startScan(cfg, nil)
}

// startScan validates and bootstraps a scan, then runs the phase pipeline on a
// background goroutine so the command loop can keep serving stop/query/snapshot
// requests while a scan is in flight. `completed` marks phases to skip (resume).
func (e *Engine) startScan(cfg config.ScanConfig, completed map[string]bool) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	cfg = config.ApplyScanProfile(cfg)
	config.ApplyScanIntensity(&cfg)
	configuredMemoryMB := cfg.MaxMemoryMB
	if strings.HasPrefix(cfg.MemoryLimitSource, "automatic_") {
		configuredMemoryMB = 0
	}
	cfg.MaxMemoryMB, cfg.MemoryLimitSource, cfg.DetectedAvailableMemoryMB = resolveMemoryLimitMB(configuredMemoryMB)
	if cfg.EnableOAST && cfg.OASTSelfHosted == nil && strings.TrimSpace(cfg.OASTServerURL) == "" {
		cfg.OASTServerURL = config.DefaultOASTServers
	}
	normalized, err := config.NormalizeTargets(cfg.Targets)
	if err != nil {
		return err
	}
	cfg.Targets = normalized
	if len(cfg.IncludeDomains) == 0 {
		cfg.IncludeDomains = deriveIncludeDomains(cfg.Targets)
	}
	if cfg.ScanID == "" {
		cfg.ScanID = deriveTargetScanID(cfg.Targets)
	}

	e.mu.Lock()
	if e.scanning {
		e.mu.Unlock()
		return errScanRunning
	}

	newScope := scope.NewEngine(cfg)
	if err := e.bootstrapPlatform(cfg, newScope); err != nil {
		e.mu.Unlock()
		return err
	}

	// Auto-detect previous incomplete scan checkpoint for this target so user
	// does not need to manually supply --scan-id or --resume flags.
	if cfg.EnableScanResume && completed == nil && e.platform != nil && e.platform.checkpoint != nil {
		if st, ok, err := e.platform.checkpoint.Latest(cfg.ScanID); err == nil && ok && len(st.Completed) > 0 {
			var status string
			if err := e.db.Conn().QueryRow("SELECT status FROM scans WHERE id = ?", cfg.ScanID).Scan(&status); err == nil && status != "completed" {
				completed = make(map[string]bool)
				for _, p := range st.Completed {
					completed[p] = true
				}
				_ = e.Emit("scan_resumed", "automatically resuming previous scan from checkpoint", map[string]interface{}{
					"scan_id":   cfg.ScanID,
					"phase":     e.platform.checkpoint.ResumeFromPhase(st),
					"completed": st.Completed,
				})
			}
		}
	}

	idCopy := cfg.ScanID
	e.activeScanID.Store(&idCopy)
	_ = e.db.EnsureScan(cfg.ScanID)
	cfgJSON, _ := json.Marshal(cfg.RedactedForStorage())
	_ = e.db.UpdateScanConfig(cfg.ScanID, string(cfgJSON))

	e.session = session.NewScanSession(cfg)
	e.scope = newScope
	e.limiter = ratelimit.New(cfg.GlobalRateLimit, cfg.PerHostRateLimit)
	client, err := httpclient.New(cfg, e.scope, e.limiter)
	if err != nil {
		e.mu.Unlock()
		return err
	}
	e.client = client
	// Module phases A-D are one logical scan. Reset the shared runner here so
	// state such as stored/second-order markers survives phase boundaries but
	// never leaks into a later scan.
	e.moduleRunner = nil
	e.resetScanQueues()
	e.session.Start()
	if e.platform != nil && e.platform.health != nil {
		e.client.OnRequest = func(err bool) {
			e.platform.health.RecordRequest(err)
		}
	}
	if err := e.resolveLoginSession(&cfg); err != nil {
		e.mu.Unlock()
		return err
	}
	e.session.Config = cfg
	e.applyAuth(cfg)
	if err := e.ensureOAST(cfg); err != nil {
		e.mu.Unlock()
		return err
	}
	if e.oast != nil {
		e.oast.SetScanID(cfg.ScanID)
	}
	e.session.SetPhase("bootstrap")
	var scanCtx context.Context
	var cancel context.CancelFunc
	if cfg.TimeBudget > 0 {
		scanCtx, cancel = context.WithTimeout(context.Background(), cfg.TimeBudget)
	} else {
		scanCtx, cancel = context.WithCancel(context.Background())
	}
	e.scanCancel = cancel
	e.scanning = true
	e.scanDone = make(chan struct{})
	e.scanErr = nil

	metricsCtx, metricsCancel := context.WithCancel(context.Background())
	e.metricsCancel = metricsCancel
	go e.runMetricsLoop(metricsCtx, cfg.ScanID)

	e.mu.Unlock()

	go e.runScanPipeline(scanCtx, cfg, completed)
	return nil
}

// WaitScanDone blocks until the active scan pipeline finishes or ctx is cancelled.
func (e *Engine) WaitScanDone(ctx context.Context) error {
	e.mu.Lock()
	ch := e.scanDone
	e.mu.Unlock()
	if ch == nil {
		return nil
	}
	select {
	case <-ch:
		e.mu.Lock()
		err := e.scanErr
		e.mu.Unlock()
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *Engine) runScanPipeline(ctx context.Context, cfg config.ScanConfig, completed map[string]bool) {
	var failedPhases []string
	var fatalPipelineErr error
	if cfg.MaxMemoryMB > 0 {
		softLimit := int64(cfg.MaxMemoryMB) * int64(bytesPerMiB) * 9 / 10
		previousLimit := debug.SetMemoryLimit(softLimit)
		defer debug.SetMemoryLimit(previousLimit)
	}
	preventSleep()
	defer restoreSleep()
	defer func() {
		finalStatus := "completed"
		var resultErr error
		if r := recover(); r != nil {
			finalStatus = "failed"
			resultErr = fmt.Errorf("scan pipeline panic: %v", r)
			_ = e.Emit("scan_error", fmt.Sprintf("scan pipeline recovered from panic: %v", r), map[string]interface{}{
				"scan_id": cfg.ScanID, "panic": fmt.Sprintf("%v", r),
			})
		} else if fatalPipelineErr != nil {
			finalStatus = "failed"
			resultErr = fatalPipelineErr
		} else if ctx.Err() != nil {
			if ctx.Err() == context.Canceled {
				finalStatus = "stopped"
			} else if ctx.Err() == context.DeadlineExceeded {
				finalStatus = "timeout"
			}
			resultErr = ctx.Err()
		} else if len(failedPhases) > 0 {
			finalStatus = "partial"
			resultErr = fmt.Errorf("scan completed with failed phases: %s", strings.Join(failedPhases, ", "))
		}
		var totalRequests int64
		if e.client != nil {
			totalRequests = e.client.TotalRequests()
		}
		if totalRequests == 0 && e.platform != nil && e.platform.health != nil {
			totalRequests = int64(e.platform.health.RequestCount())
		}
		startedAt := time.Now().UTC()
		if e.session != nil {
			snap := e.session.Snapshot()
			if !snap.StartedAt.IsZero() {
				startedAt = snap.StartedAt
			}
		}
		completedAt := time.Now().UTC()
		if e.db != nil {
			if err := e.db.UpdateScanFinished(cfg.ScanID, finalStatus, totalRequests, startedAt, completedAt); err != nil && resultErr == nil {
				resultErr = fmt.Errorf("persist final scan status: %w", err)
			}
		}
		if finalStatus == "stopped" {
			_ = e.Emit("scan_stopped", "scan stopped", map[string]interface{}{"scan_id": cfg.ScanID, "was_running": true})
		}

		// An Interactsh registration is a scan-scoped, expiring remote session.
		// Detach and close it before advertising the scan as finished; otherwise
		// the next scan can inherit a stale registration and flood the event stream
		// with polling/failover errors until the process state is reset.
		e.mu.Lock()
		listener := e.oast
		e.oast = nil
		if e.metricsCancel != nil {
			e.metricsCancel()
			e.metricsCancel = nil
		}
		e.mu.Unlock()
		if listener != nil {
			listener.Stop()
		}

		e.mu.Lock()
		e.scanning = false
		e.scanErr = resultErr
		if e.scanCancel != nil {
			e.scanCancel()
			e.scanCancel = nil
		}
		if e.scanDone != nil {
			close(e.scanDone)
		}
		e.mu.Unlock()
	}()

	done := func(phase string) bool { return completed != nil && completed[phase] }
	completedList := []string{"bootstrap"}
	for _, p := range []string{
		"preflight", "fingerprint", "learning_waf", "api_import", "crawling", "sensor_discovery", "js_analysis", "shadow_api",
		"parameter_discovery", "fuzzing", "bypass403", "reflection", "vuln_modules", "oast_drain",
	} {
		if done(p) {
			completedList = append(completedList, p)
		}
	}

	phaseStatus := make(map[string]string)
	if e.platform != nil {
		if st, ok, err := e.platform.checkpoint.Latest(cfg.ScanID); err == nil && ok {
			if st.PhaseStatus != nil {
				phaseStatus = st.PhaseStatus
			}
		}
	}

	markSuccess := func(phase string) {
		completedList = append(completedList, phase)
		phaseStatus[phase] = "success"
		e.checkpointPhase(cfg.ScanID, phase, append([]string{}, completedList...), phaseStatus)
	}

	markFailed := func(phase string) {
		alreadyFailed := false
		for _, failed := range failedPhases {
			if failed == phase {
				alreadyFailed = true
				break
			}
		}
		if !alreadyFailed {
			failedPhases = append(failedPhases, phase)
		}
		phaseStatus[phase] = "failed"
		e.checkpointPhase(cfg.ScanID, phase, append([]string{}, completedList...), phaseStatus)
	}

	markSkipped := func(phase string) {
		completedList = append(completedList, phase)
		phaseStatus[phase] = "skipped"
		e.checkpointPhase(cfg.ScanID, phase, append([]string{}, completedList...), phaseStatus)
	}

	stopped := func() bool {
		if ctx.Err() == nil {
			return false
		}
		e.session.Stop()
		return true
	}

	_ = e.Emit("scan_started", "scan started", map[string]interface{}{
		"scan_id":                      cfg.ScanID,
		"targets":                      cfg.Targets,
		"max_pages":                    cfg.EffectiveMaxPages(),
		"max_endpoints":                cfg.MaxEndpointsLimit(),
		"max_depth":                    cfg.MaxDepth,
		"subdomain_count":              cfg.SubdomainCount,
		"request_budget":               cfg.RequestBudget,
		"crawler_request_budget":       cfg.EffectiveCrawlerBudget(),
		"payload_budget":               cfg.PayloadBudget,
		"global_rate_limit":            cfg.GlobalRateLimit,
		"scan_intensity":               cfg.ScanIntensity,
		"scan_profile":                 cfg.SmartScanProfile,
		"passive_mode":                 cfg.PassiveMode,
		"memory_limit_mb":              cfg.MaxMemoryMB,
		"memory_limit_source":          cfg.MemoryLimitSource,
		"detected_available_memory_mb": cfg.DetectedAvailableMemoryMB,
		"oast_enabled":                 cfg.EnableOAST,
		"proxy_enabled":                cfg.ProxyURL != "",
		"proxy_endpoint":               config.SafeProxyURL(cfg.ProxyURL),
		"insecure_tls":                 cfg.InsecureSkipVerify,
	})
	_ = e.Emit("log", "core engine foundation initialized", nil)
	_ = e.Emit("phase_started", "phase bootstrap", map[string]interface{}{"phase": "bootstrap"})
	_ = e.Emit("phase_finished", "phase bootstrap", map[string]interface{}{"phase": "bootstrap"})

	targets := cfg.Targets
	if !done("preflight") {
		if err := e.runPreflightValidation(ctx, cfg); err != nil {
			if ctx.Err() != nil {
				return
			}
			fatalPipelineErr = err
			markFailed("preflight")
			_ = e.Emit("scan_error", err.Error(), map[string]interface{}{"phase": "preflight"})
			e.session.Stop()
			return
		}
		markSuccess("preflight")
	}

	// ── Phase 1: Technology + WAF fingerprinting ──────────────────────────
	if !done("fingerprint") {
		hasError := false
		for _, target := range targets {
			if stopped() {
				return
			}
			if err := e.runFingerprintPhase(ctx, target); err != nil {
				_ = e.Emit("scan_error", err.Error(), map[string]interface{}{"target": target, "phase": "fingerprinting"})
				hasError = true
			}
		}
		if hasError {
			markFailed("fingerprint")
		} else {
			markSuccess("fingerprint")
		}
	}
	if stopped() {
		return
	}

	// ── Phase 2: WAF learning / calibration ────────────────────────────────
	if !done("learning_waf") {
		if cfg.EnableWAFDetection {
			timeout := 90 * time.Second
			opts := wafintel.CalibrationOptions{MaxStrategies: 3}
			if cfg.ScanIntensity == "fast" {
				timeout = 12 * time.Second
				opts.MaxStrategies = 1
			}
			learnCtx, cancel := context.WithTimeout(ctx, timeout)
			if err := e.runLearningWAFPhase(learnCtx, targets, opts); err != nil {
				_ = e.Emit("log", "waf learning skipped: "+err.Error(), map[string]interface{}{"scan_id": cfg.ScanID})
				markFailed("learning_waf")
			} else {
				markSuccess("learning_waf")
			}
			cancel()
		} else {
			_ = e.Emit("phase_started", "learning_waf", map[string]interface{}{"phase": "learning_waf", "skipped": true})
			_ = e.Emit("log", "WAF learning skipped; fingerprint profile used", map[string]interface{}{"scan_id": cfg.ScanID})
			_ = e.Emit("phase_finished", "learning_waf", map[string]interface{}{"phase": "learning_waf", "skipped": true})
			markSkipped("learning_waf")
		}
	}
	if stopped() {
		return
	}

	crawlerTargets := uniqueURLSeeds(targets)

	// API definitions are imported before crawling so their typed request
	// templates participate in parameter discovery and module scheduling.
	if !done("api_import") && len(cfg.APIImportFiles) > 0 {
		if err := e.runAPIImportPhase(ctx, cfg.APIImportFiles, targets[0]); err != nil {
			_ = e.Emit("scan_error", err.Error(), map[string]interface{}{"phase": "api_import"})
			markFailed("api_import")
		} else {
			markSuccess("api_import")
		}
	} else if !done("api_import") {
		markSkipped("api_import")
	}
	if stopped() {
		return
	}

	// ── Phase 3: Deep crawl (authenticated) ─────────────────────────────────
	if loginSessionGuardEnabled(cfg) {
		if err := e.ensureAuthenticatedSession(ctx); err != nil {
			_ = e.Emit("scan_error", err.Error(), map[string]interface{}{"phase": "session_guard_crawl"})
			markFailed("session_guard_crawl")
			e.session.Stop()
			return
		}
		markSuccess("session_guard_crawl")
	}
	if !done("crawling") {
		_ = e.Emit("scan_progress", "crawling in-scope targets", map[string]interface{}{
			"scan_id": cfg.ScanID, "phase": "crawling", "targets": len(crawlerTargets),
		})
		if err := e.runCrawlerPhase(ctx, crawlerTargets); err != nil {
			_ = e.Emit("scan_error", err.Error(), map[string]interface{}{"phase": "crawling"})
			markFailed("crawling")
		} else {
			markSuccess("crawling")
		}
	}
	if stopped() {
		return
	}

	// Runtime sensor agent discovery.
	// The collector starts automatically, but correlation headers are enabled
	// only when the target identifies an installed Akca application agent.
	if !done("sensor_discovery") && cfg.EnableRuntimeSensor && e.platform != nil && e.platform.sensor != nil {
		if err := e.runRuntimeSensorDiscovery(ctx, crawlerTargets); err != nil {
			_ = e.Emit("scan_error", err.Error(), map[string]interface{}{"phase": "sensor_discovery"})
			markFailed("sensor_discovery")
		} else {
			markSuccess("sensor_discovery")
		}
	} else if !done("sensor_discovery") {
		markSkipped("sensor_discovery")
	}
	if stopped() {
		return
	}

	// ── Phase 5: JavaScript analysis (hidden APIs / endpoints in JS) ────────
	if !done("js_analysis") && cfg.EnableJSAnalysis {
		var err1, err2 error
		if err1 = e.runJSAnalysisPhase(ctx); err1 != nil {
			_ = e.Emit("scan_error", err1.Error(), map[string]interface{}{"phase": "js_analysis"})
		}
		if err2 = e.runJSDiscoveredCrawlPhase(ctx); err2 != nil {
			_ = e.Emit("scan_error", err2.Error(), map[string]interface{}{"phase": "js_api_crawl"})
		}
		if err1 != nil || err2 != nil {
			markFailed("js_analysis")
		} else {
			markSuccess("js_analysis")
		}
	} else if !done("js_analysis") {
		markSkipped("js_analysis")
	}
	if stopped() {
		return
	}

	// Contract/runtime comparison is an API inventory signal; it deliberately
	// does not create a vulnerability finding without an exploit proof.
	if !done("shadow_api") && len(cfg.APIImportFiles) > 0 {
		if err := e.runShadowAPIPhase(ctx, cfg.ScanID); err != nil {
			_ = e.Emit("scan_error", err.Error(), map[string]interface{}{"phase": "shadow_api"})
			markFailed("shadow_api")
		} else {
			markSuccess("shadow_api")
		}
	} else if !done("shadow_api") {
		markSkipped("shadow_api")
	}
	if stopped() {
		return
	}

	// ── Phase 6: Parameter + hidden parameter discovery ─────────────────────
	if !done("parameter_discovery") && !cfg.PassiveMode {
		if err := e.runParameterDiscoveryPhase(ctx); err != nil {
			_ = e.Emit("scan_error", err.Error(), map[string]interface{}{"phase": "parameter_discovery"})
			markFailed("parameter_discovery")
		} else {
			markSuccess("parameter_discovery")
		}
	} else if !done("parameter_discovery") {
		_ = e.Emit("phase_started", "parameter discovery", map[string]interface{}{"phase": "parameter_discovery", "skipped": true, "reason": "passive_mode"})
		_ = e.Emit("phase_finished", "parameter discovery", map[string]interface{}{"phase": "parameter_discovery", "skipped": true})
		markSkipped("parameter_discovery")
	}
	if stopped() {
		return
	}

	// ── Phase 7: Fuzzing (exposed paths, actuator, archives) ────────────────
	if !done("fuzzing") && cfg.EnableFuzzing {
		if err := e.runFuzzingPhase(ctx, crawlerTargets); err != nil {
			_ = e.Emit("scan_error", err.Error(), map[string]interface{}{"phase": "fuzzing"})
			markFailed("fuzzing")
		} else {
			markSuccess("fuzzing")
		}
	} else if !done("fuzzing") {
		_ = e.Emit("phase_started", "fuzzing", map[string]interface{}{"phase": "fuzzing", "skipped": true})
		_ = e.Emit("log", "fuzzing phase disabled by config", map[string]interface{}{"scan_id": cfg.ScanID})
		_ = e.Emit("phase_finished", "fuzzing", map[string]interface{}{"phase": "fuzzing", "skipped": true})
		markSkipped("fuzzing")
	}
	if stopped() {
		return
	}

	// ── Phase 8: 403 bypass attempts ────────────────────────────────────────
	if !done("bypass403") && cfg.Enable403BypassChecks {
		e.ingestAuthBlockedFromCrawl(cfg.ScanID)
		if e.queue403 == nil {
			e.hydrateQueue403FromDB(cfg.ScanID)
		}
		if err := e.runBypass403Phase(ctx); err != nil {
			_ = e.Emit("scan_error", err.Error(), map[string]interface{}{"phase": "bypass403"})
			markFailed("bypass403")
		} else {
			markSuccess("bypass403")
		}
	} else if !done("bypass403") {
		markSkipped("bypass403")
	}
	if stopped() {
		return
	}

	// ── Phase 9: Reflection analysis + context-aware payload generation ─────
	if !done("reflection") && !cfg.PassiveMode {
		if err := e.runReflectionPayloadPhase(ctx); err != nil {
			_ = e.Emit("scan_error", err.Error(), map[string]interface{}{"phase": "reflection"})
			markFailed("reflection")
		} else {
			markSuccess("reflection")
		}
	} else if !done("reflection") {
		_ = e.Emit("phase_started", "reflection and payload generation", map[string]interface{}{"phase": "reflection", "skipped": true, "reason": "passive_mode"})
		_ = e.Emit("phase_finished", "reflection and payload generation", map[string]interface{}{"phase": "reflection", "skipped": true})
		markSkipped("reflection")
	}
	if stopped() {
		return
	}

	// ── Phase 10: Vulnerability modules (SQLi, XSS, SSRF, etc.) ───────────────
	if loginSessionGuardEnabled(cfg) {
		if err := e.ensureAuthenticatedSession(ctx); err != nil {
			_ = e.Emit("scan_error", err.Error(), map[string]interface{}{"phase": "session_guard_modules"})
			markFailed("session_guard_modules")
			e.session.Stop()
			return
		}
		markSuccess("session_guard_modules")
	}
	if !done("vuln_modules") {
		if err := e.runVulnModulesSequential(ctx); err != nil {
			_ = e.Emit("scan_error", err.Error(), map[string]interface{}{"phase": "vuln_modules"})
			markFailed("vuln_modules")
		} else {
			markSuccess("vuln_modules")
		}
	}
	if stopped() {
		return
	}

	// ── Phase 11: OAST callback drain (blind SSRF/XSS/SQLi confirmation) ────
	if !done("oast_drain") {
		e.runOASTDrainPhase(ctx, cfg.ScanID)
		markSuccess("oast_drain")
	}
	if stopped() {
		return
	}

	e.finalizePlatform(cfg.ScanID)

	var currentRequests int64
	if e.client != nil {
		currentRequests = e.client.TotalRequests()
	}
	if currentRequests == 0 && e.platform != nil && e.platform.health != nil {
		currentRequests = int64(e.platform.health.RequestCount())
	}
	startedAt := time.Now().UTC()
	if e.session != nil {
		snap := e.session.Snapshot()
		if !snap.StartedAt.IsZero() {
			startedAt = snap.StartedAt
		}
	}
	completedAt := time.Now().UTC()
	if e.db != nil {
		_ = e.db.UpdateScanFinished(cfg.ScanID, "running", currentRequests, startedAt, completedAt)
	}

	if !cfg.SkipAutoReport {
		e.checkpointPhase(cfg.ScanID, "report_generation", append([]string{}, completedList...), phaseStatus)
		if err := e.runReportPhase(ctx, cfg.ScanID, false); err != nil {
			_ = e.Emit("scan_error", err.Error(), map[string]interface{}{"scan_id": cfg.ScanID, "phase": "report_generation"})
			markFailed("report_generation")
		} else {
			markSuccess("report_generation")
		}
	}

	status := "completed"
	if len(failedPhases) > 0 {
		status = "partial"
	}
	_ = e.Emit("scan_finished", "scan finished", map[string]interface{}{
		"scan_id": cfg.ScanID, "status": status, "failed_phases": append([]string(nil), failedPhases...),
	})
	e.session.Stop()
}

// applyAuth wires the configured authentication into the active HTTP client so
// authenticated scans actually send credentials. Caller must hold e.mu.
func (e *Engine) applyAuth(cfg config.ScanConfig) {
	cookies := map[string]string{}
	headers := map[string]string{}
	for k, v := range cfg.SessionCookies {
		cookies[k] = v
	}
	for k, v := range cfg.CustomHeaders {
		headers[k] = v
	}
	if len(cfg.ApiKeys) > 0 {
		for k, v := range cfg.ApiKeys {
			headers[k] = v
		}
	}
	if len(cfg.Authentication) > 0 {
		for k, v := range cfg.Authentication {
			if strings.EqualFold(k, "cookie") {
				for ck, cv := range parseCookieHeader(v) {
					cookies[ck] = cv
				}
				continue
			}
			headers[k] = v
		}
	}
	if len(cookies) > 0 || len(headers) > 0 {
		var hd, ck map[string]string
		if len(headers) > 0 {
			hd = headers
		}
		if len(cookies) > 0 {
			ck = cookies
		}
		e.client.SetSession(ck, hd)
	}
	if len(cfg.AuthProfiles) > 0 && e.platform != nil && e.platform.auth != nil {
		e.platform.auth.ApplyProfile(e.client, cfg.AuthProfiles[0])
	}
}

func parseCookieHeader(raw string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(raw, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 && kv[0] != "" {
			out[kv[0]] = kv[1]
		}
	}
	return out
}

func (e *Engine) StopScan() error {
	e.mu.Lock()
	scanning := e.scanning
	if scanning && e.scanCancel != nil {
		e.scanCancel()
	}
	e.session.Stopping()
	id := e.session.ID
	e.mu.Unlock()
	return e.Emit("scan_stopping", "scan stopping", map[string]interface{}{"scan_id": id, "was_running": scanning})
}

func (e *Engine) Snapshot() ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	snap := e.session.Snapshot()
	return json.Marshal(snap)
}

func (e *Engine) HandleCommand(input CommandInput) error {
	switch input.Action {
	case "start_scan":
		cfg := e.currentSession().Config
		if len(input.Config) > 0 {
			if err := json.Unmarshal(input.Config, &cfg); err != nil {
				return err
			}
		}
		return e.StartScan(cfg)
	case "stop_scan":
		return e.StopScan()
	case "get_snapshot":
		b, err := e.Snapshot()
		if err != nil {
			return err
		}
		return e.Emit("scan_snapshot", string(b), nil)
	case "resume_scan":
		return e.ResumeScan(input)
	case "query":
		return e.HandleQuery(input)
	default:
		return e.Emit("log", "unknown command: "+input.Action, nil)
	}
}

func (e *Engine) HTTPClient() *httpclient.Client {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.client
}

// currentSession returns the active session pointer guarded by the engine lock,
// safe to call while a scan goroutine is running.
func (e *Engine) currentSession() *session.ScanSession {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.session
}

func (e *Engine) Scope() *scope.Engine {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.scope
}

func (e *Engine) RequestQueue() *queue.RequestQueue {
	return e.reqQueue
}

func (e *Engine) DB() *storage.DB {
	return e.db
}

func (e *Engine) moduleTargetLimit() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.session != nil {
		return e.session.Config.ModuleTargetLimit()
	}
	return 500
}

func (e *Engine) ensureOAST(cfg config.ScanConfig) error {
	desired := strings.TrimSpace(cfg.OASTServerURL)
	if cfg.OASTSelfHosted != nil {
		desired = "self-hosted://" + cfg.OASTSelfHosted.Domain + "|" + cfg.OASTSelfHosted.HTTPAddr + "|" +
			cfg.OASTSelfHosted.HTTPSAddr + "|" + cfg.OASTSelfHosted.DNSAddr + "|" +
			cfg.OASTSelfHosted.SMTPAddr + "|" + cfg.OASTSelfHosted.LDAPAddr
	} else if desired == "" {
		desired = config.DefaultOASTServers
	}
	if !cfg.EnableOAST {
		if e.oast != nil {
			e.oast.Stop()
			e.oast = nil
		}
		return nil
	}
	// Never reuse an existing listener merely because its configured endpoint
	// is unchanged. Remote OAST credentials and correlation domains expire and
	// belong to one scan run, so each run must register a fresh session.
	if e.oast != nil {
		e.oast.Stop()
		e.oast = nil
	}
	listenerConfig := oast.Config{PollInterval: cfg.OASTPollInterval}
	if cfg.OASTSelfHosted != nil {
		listenerConfig.SelfHosted = &oast.SelfHostedConfig{
			Domain: cfg.OASTSelfHosted.Domain, HTTPAddr: cfg.OASTSelfHosted.HTTPAddr,
			HTTPSAddr: cfg.OASTSelfHosted.HTTPSAddr, TLSCertFile: cfg.OASTSelfHosted.TLSCertFile,
			TLSKeyFile: cfg.OASTSelfHosted.TLSKeyFile, DNSAddr: cfg.OASTSelfHosted.DNSAddr,
			SMTPAddr: cfg.OASTSelfHosted.SMTPAddr, LDAPAddr: cfg.OASTSelfHosted.LDAPAddr,
		}
	} else {
		listenerConfig.ServerURL = desired
	}
	listenerConfig.HTTPClient = e.client.HTTPClient()
	listener, err := oast.NewListener(e.db, e.Emit, listenerConfig)
	if err != nil {
		return err
	}
	if err := listener.Start(e.oastCtx); err != nil {
		_ = e.Emit("oast_failed", "OAST startup failed after trying the configured server order: "+err.Error(), map[string]interface{}{
			"scan_id":      cfg.ScanID,
			"server_order": strings.Split(desired, ","), "fallback_stage": "startup_registration",
			"runtime_failover": false, "blind_coverage": false,
		})
		_ = e.Emit("coverage_gap", "blind SSRF/XSS/XXE/OOB coverage unavailable (all configured OAST servers unreachable)", map[string]interface{}{
			"scan_id": cfg.ScanID, "module": "oast", "reason": err.Error(), "server_order": strings.Split(desired, ","),
		})
		return nil
	}
	e.oast = listener
	return nil
}

func (e *Engine) OAST() *oast.Listener {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.oast
}

func (e *Engine) SaveConfig(path string) error {
	return config.Save(path, e.session.Config)
}

func (e *Engine) LoadConfig(path string) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.session.Config = cfg
	return nil
}

func (e *Engine) ProbeTarget(ctx context.Context, url string) error {
	_, err := e.client.Do(ctx, "GET", url, nil, nil)
	if err != nil {
		_ = e.Emit("scope_blocked", err.Error(), map[string]interface{}{"url": url})
		return err
	}
	return nil
}

// deriveIncludeDomains builds exact-host scope rules from configured targets.
func deriveIncludeDomains(targets []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, t := range targets {
		raw := strings.TrimSpace(t)
		if raw == "" {
			continue
		}
		if !strings.Contains(raw, "://") {
			raw = "https://" + raw
		}
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		host := strings.ToLower(u.Host)
		if host == "" {
			host = strings.ToLower(u.Hostname())
		}
		if host == "" {
			continue
		}
		// Strip standard default ports (:80 for http, :443 for https)
		if (u.Scheme == "http" && strings.HasSuffix(host, ":80")) ||
			(u.Scheme == "https" && strings.HasSuffix(host, ":443")) {
			host = strings.ToLower(u.Hostname())
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	return out
}

func uniqueURLSeeds(urls []string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(raw string) {
		if _, ok := seen[raw]; ok {
			return
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
	}
	for _, raw := range urls {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}

		// Keep the exact URL as the primary seed, but also crawl the site's
		// root. A deep-link target (for example /ssti) often has no links back
		// to the lab/site index; without the root seed the crawler can never
		// discover sibling routes even though the whole host is in scope.
		add(raw)
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			continue
		}
		u.Path = "/"
		u.RawPath = ""
		u.RawQuery = ""
		u.ForceQuery = false
		u.Fragment = ""
		add(u.String())
	}
	return out
}

func deriveTargetScanID(targets []string) string {
	if len(targets) == 0 {
		b := make([]byte, 4)
		_, _ = rand.Read(b)
		return fmt.Sprintf("scan-%d-%s", time.Now().UnixNano(), hex.EncodeToString(b))
	}
	sorted := append([]string(nil), targets...)
	sort.Strings(sorted)
	hash := sha256.Sum256([]byte(strings.Join(sorted, "|")))
	return fmt.Sprintf("scan-%s", hex.EncodeToString(hash[:6]))
}

func ConfigDir() (string, error) {
	dir, err := storage.DataDir()
	if err != nil {
		return "", err
	}
	cfgDir := dir + string(os.PathSeparator) + "config"
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		return "", err
	}
	return cfgDir, nil
}

func (e *Engine) runMetricsLoop(ctx context.Context, scanID string) {
	defer func() {
		if recovered := recover(); recovered != nil {
			_ = e.Emit("scan_error", fmt.Sprintf("metrics worker recovered from panic: %v", recovered), map[string]interface{}{
				"scan_id": scanID, "worker": "metrics",
			})
		}
	}()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var lastReqCount int
	var lastCaptureTime = time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.mu.Lock()
			health := e.platform.health
			reqQueue := e.reqQueue
			oast := e.oast
			sess := e.session
			cancelScan := e.scanCancel
			moduleRunner := e.moduleRunner
			e.mu.Unlock()

			var heapMB int
			var processMemoryMB int
			var memoryLimitMB int
			if sess != nil {
				snapshot := sess.Snapshot()
				memoryLimitMB = snapshot.Config.MaxMemoryMB
				var memory runtime.MemStats
				runtime.ReadMemStats(&memory)
				heapMB = int(memory.HeapAlloc >> 20)
				processBytes, processErr := processMemoryBytes()
				if processErr == nil {
					processMemoryMB = int(processBytes >> 20)
				}
				if snapshot.Config.MaxMemoryMB > 0 {
					limitBytes := uint64(snapshot.Config.MaxMemoryMB) << 20
					usedBytes := memory.HeapAlloc
					resource := "heap_memory"
					if processBytes > usedBytes {
						usedBytes = processBytes
						resource = "process_memory"
					}
					if usedBytes >= limitBytes {
						_ = e.Emit("resource_limit_reached", "scan stopped before exhausting process memory; resume from checkpoint with --resume", map[string]interface{}{
							"scan_id": scanID, "resource": resource, "heap_mb": memory.HeapAlloc >> 20,
							"process_memory_mb": processMemoryMB,
							"limit_mb":          snapshot.Config.MaxMemoryMB, "recoverable": true,
						})
						if cancelScan != nil {
							cancelScan()
						}
						return
					}
				}
			}

			if health == nil {
				continue
			}

			now := time.Now()
			elapsed := now.Sub(lastCaptureTime).Seconds()
			if elapsed <= 0 {
				elapsed = 1
			}
			reqCount := int(health.RequestCount())
			payloadProbes := 0
			if moduleRunner != nil {
				payloadProbes = int(moduleRunner.ProbeCount())
			}
			reqRate := float64(reqCount-lastReqCount) / elapsed
			lastReqCount = reqCount
			lastCaptureTime = now

			oastStatus := "disabled"
			if oast != nil {
				oastStatus = "listening"
			}

			qSize := 0
			if reqQueue != nil {
				qSize = reqQueue.Len()
			}

			var discovered int
			_ = e.db.Conn().QueryRow("SELECT COUNT(*) FROM endpoints WHERE scan_id = ?", scanID).Scan(&discovered)

			var tested int
			if sess != nil {
				snap := sess.Snapshot()
				tested = snap.Metrics["endpoints_tested"]
			}

			// Estimate tested based on active phase if we don't have exact metrics
			if sess != nil {
				snap := sess.Snapshot()
				phase := snap.Phase

				var progressBase int
				switch phase {
				case "bootstrap", "fingerprint":
					progressBase = 5
				case "crawling", "sensor_discovery", "js_api_crawl", "js_analysis", "shadow_api":
					progressBase = 20
				case "fuzzing", "parameter_discovery", "bypass403", "learning_waf":
					progressBase = 50
				case "vuln_modules", "vuln_modules_a", "vuln_modules_b", "vuln_modules_c", "vuln_modules_d", "reflection":
					progressBase = 75
				case "report_generation", "oast_drain":
					progressBase = 95
				default:
					if strings.HasPrefix(phase, "vuln_module_") {
						progressBase = 75
					} else {
						progressBase = 0
					}
				}

				if progressBase > 0 {
					estimatedTested := (discovered * progressBase) / 100
					if estimatedTested > tested {
						tested = estimatedTested
					}
				}
			}

			if tested > discovered {
				tested = discovered
			}
			remaining := discovered - tested
			if qSize > remaining {
				remaining = qSize
			}

			if sess != nil {
				sess.SetMetric("endpoints_discovered", discovered)
				sess.SetMetric("endpoints_tested", tested)
				sess.SetMetric("endpoints_remaining", remaining)
			}

			// Capture in sqlite
			_, _ = health.Capture(scanID, map[string]float64{"crawler": 1.0}, oastStatus, map[string]int{"crawl": qSize})

			_ = e.Emit("health_snapshot", "health metrics update", map[string]interface{}{
				"request_rate":         reqRate,
				"request_count":        reqCount,
				"payload_probes":       payloadProbes,
				"heap_mb":              heapMB,
				"process_memory_mb":    processMemoryMB,
				"memory_limit_mb":      memoryLimitMB,
				"endpoints_discovered": discovered,
				"endpoints_tested":     tested,
				"endpoints_remaining":  remaining,
			})
		}
	}
}
