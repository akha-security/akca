package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/distributed"
	"github.com/akha-security/akca/engine/internal/events"
	"github.com/akha-security/akca/engine/internal/fuzzing"
	"github.com/akha-security/akca/engine/internal/httpclient"
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
	metricsCancel context.CancelFunc
	jobs          *distributed.Coordinator
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
	e.mu.Lock()
	if e.scanning && e.scanCancel != nil {
		e.scanCancel()
	}
	if e.metricsCancel != nil {
		e.metricsCancel()
	}
	e.mu.Unlock()
	e.shutdownPlatform()
	if e.oast != nil {
		e.oast.Stop()
	}
	if e.oastCancel != nil {
		e.oastCancel()
	}
	if e.stopCh != nil {
		close(e.stopCh)
	}
	_ = e.batcher.Close()
	return e.db.Close()
}

func (e *Engine) Emit(eventType, message string, payload map[string]interface{}) error {
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
		cfg.ScanID = fmt.Sprintf("scan-%d", time.Now().Unix())
	}

	e.mu.Lock()
	if e.scanning {
		e.mu.Unlock()
		return errScanRunning
	}
	_ = e.db.EnsureScan(cfg.ScanID)
	e.session = session.NewScanSession(cfg)
	e.scope = scope.NewEngine(cfg)
	e.limiter = ratelimit.New(cfg.GlobalRateLimit, cfg.PerHostRateLimit)
	client, err := httpclient.New(cfg, e.scope, e.limiter)
	if err != nil {
		e.mu.Unlock()
		return err
	}
	e.client = client
	e.resetScanQueues()
	e.session.Start()
	if err := e.bootstrapPlatform(cfg); err != nil {
		e.mu.Unlock()
		return err
	}
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
	scanCtx, cancel := context.WithCancel(context.Background())
	e.scanCancel = cancel
	e.scanning = true
	e.scanDone = make(chan struct{})

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
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *Engine) runScanPipeline(ctx context.Context, cfg config.ScanConfig, completed map[string]bool) {
	defer func() {
		e.mu.Lock()
		e.scanning = false
		if e.scanCancel != nil {
			e.scanCancel()
			e.scanCancel = nil
		}
		if e.metricsCancel != nil {
			e.metricsCancel()
			e.metricsCancel = nil
		}
		if e.scanDone != nil {
			close(e.scanDone)
			e.scanDone = nil
		}
		e.mu.Unlock()
	}()

	done := func(phase string) bool { return completed != nil && completed[phase] }
	completedList := []string{"bootstrap"}
	for _, p := range []string{
		"fingerprint", "learning_waf", "api_import", "crawling", "sensor_discovery", "js_analysis", "shadow_api",
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
		"scan_id":           cfg.ScanID,
		"targets":           cfg.Targets,
		"max_pages":         cfg.MaxPages,
		"request_budget":    cfg.RequestBudget,
		"global_rate_limit": cfg.GlobalRateLimit,
		"scan_intensity":    cfg.ScanIntensity,
		"scan_profile":      cfg.SmartScanProfile,
		"oast_enabled":      cfg.EnableOAST,
		"proxy_enabled":     cfg.ProxyURL != "",
		"proxy_endpoint":    config.SafeProxyURL(cfg.ProxyURL),
		"insecure_tls":      cfg.InsecureSkipVerify,
	})
	_ = e.Emit("log", "core engine foundation initialized", nil)
	_ = e.Emit("phase_started", "phase bootstrap", map[string]interface{}{"phase": "bootstrap"})
	_ = e.Emit("phase_finished", "phase bootstrap", map[string]interface{}{"phase": "bootstrap"})

	targets := cfg.Targets

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
	if cfg.EnableRuntimeSensor && e.platform != nil && e.platform.sensor != nil {
		err := e.runRuntimeSensorDiscovery(ctx, crawlerTargets)
		if !done("sensor_discovery") {
			if err != nil {
				_ = e.Emit("scan_error", err.Error(), map[string]interface{}{"phase": "sensor_discovery"})
				markFailed("sensor_discovery")
			} else {
				markSuccess("sensor_discovery")
			}
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
	if !done("parameter_discovery") {
		if err := e.runParameterDiscoveryPhase(ctx); err != nil {
			_ = e.Emit("scan_error", err.Error(), map[string]interface{}{"phase": "parameter_discovery"})
			markFailed("parameter_discovery")
		} else {
			markSuccess("parameter_discovery")
		}
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
	if !done("reflection") {
		if err := e.runReflectionPayloadPhase(ctx); err != nil {
			_ = e.Emit("scan_error", err.Error(), map[string]interface{}{"phase": "reflection"})
			markFailed("reflection")
		} else {
			markSuccess("reflection")
		}
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
		hasError := false
		for _, run := range []func(context.Context) error{
			e.runVulnModulesPhaseA, e.runVulnModulesPhaseB,
			e.runVulnModulesPhaseC, e.runVulnModulesPhaseD,
		} {
			if stopped() {
				return
			}
			if err := run(ctx); err != nil {
				_ = e.Emit("scan_error", err.Error(), map[string]interface{}{"phase": "vuln_modules"})
				hasError = true
			}
		}
		if hasError {
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
	if !cfg.SkipAutoReport {
		e.checkpointPhase(cfg.ScanID, "report_generation", append([]string{}, completedList...), phaseStatus)
		if err := e.runReportPhase(ctx, cfg.ScanID, false); err != nil {
			_ = e.Emit("scan_error", err.Error(), nil)
		}
	}

	_ = e.Emit("scan_finished", "scan finished", map[string]interface{}{"scan_id": cfg.ScanID})
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
	return e.Emit("scan_stopped", "scan stopping", map[string]interface{}{"scan_id": id, "was_running": scanning})
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
	if e.oast != nil && e.oast.ServerURL() == desired {
		return nil
	}
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
	listener, err := oast.NewListener(e.db, e.Emit, listenerConfig)
	if err != nil {
		return err
	}
	if err := listener.Start(e.oastCtx); err != nil {
		_ = e.Emit("oast_failed", "OAST initialization failed: "+err.Error(), map[string]interface{}{
			"server": desired, "blind_coverage": false,
		})
		_ = e.Emit("coverage_gap", "blind SSRF/XSS/XXE/OOB coverage unavailable", map[string]interface{}{
			"module": "oast", "reason": err.Error(),
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
		host := strings.ToLower(u.Hostname())
		if host == "" {
			continue
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
	for _, raw := range urls {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if _, ok := seen[raw]; ok {
			continue
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
	}
	return out
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
			e.mu.Unlock()

			if health == nil {
				continue
			}

			now := time.Now()
			elapsed := now.Sub(lastCaptureTime).Seconds()
			if elapsed <= 0 {
				elapsed = 1
			}
			reqCount := int(health.RequestCount())
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
					progressBase = 0
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
				"endpoints_discovered": discovered,
				"endpoints_tested":     tested,
				"endpoints_remaining":  remaining,
			})
		}
	}
}
