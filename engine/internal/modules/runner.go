package modules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/learning"
	"github.com/akha-security/akca/engine/internal/oast"
	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/reflection"
	"github.com/akha-security/akca/engine/internal/safemutation"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/secretscan"
	"github.com/akha-security/akca/engine/internal/sensor"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/verification"
)

type HTTPDoer interface {
	Do(ctx context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error)
}

type OASTClient interface {
	GenerateURL(payloadID, endpointURL, parameter, vulnClass string, findingID int64) (oast.GeneratedURL, error)
}

type BrowserRenderer interface {
	Render(ctx context.Context, rawURL string) (string, error)
}

type TLSInspector interface {
	Inspect(ctx context.Context, rawURL string) (TLSInspection, error)
}

type WebSocketProber interface {
	Probe(ctx context.Context, rawURL, payload string) (httpclient.RequestResponse, error)
}

type SmugglingProber interface {
	Probe(ctx context.Context, rawURL, variant string) (SmugglingProbeResult, error)
}

type ScanTarget struct {
	EndpointURL        string
	Method             string
	Parameter          string
	Location           string
	Profile            reflection.ReflectionProfile
	Payloads           payloadgen.GenerationResult
	EndpointType       string
	RiskTags           []string
	RecommendedModules []string
	Priority           int
	BodyTemplate       string
	RequestTemplate    reflection.RequestTemplate
}

type Evidence struct {
	Module          string                    `json:"module"`
	Signal          string                    `json:"signal"`
	Payload         payloadgen.Payload        `json:"payload"`
	Parameter       string                    `json:"parameter,omitempty"`
	Location        string                    `json:"location,omitempty"`
	ResponseMarkers []string                  `json:"response_markers,omitempty"`
	MethodVariants  []MethodVariantEvidence   `json:"method_variants,omitempty"`
	Request         httpclient.RequestRecord  `json:"request"`
	Response        httpclient.ResponseRecord `json:"response"`
	Verification    verification.Result       `json:"verification"`
	OASTURL         string                    `json:"oast_url,omitempty"`
	StoredMarker    string                    `json:"stored_marker,omitempty"`
	ReplayPlan      []ReplayStep              `json:"replay_plan,omitempty"`
	DetectedAt      time.Time                 `json:"detected_at"`
}

type MethodVariantEvidence struct {
	Method   string                    `json:"method"`
	Location string                    `json:"location"`
	Signal   string                    `json:"signal"`
	Payload  payloadgen.Payload        `json:"payload"`
	Request  httpclient.RequestRecord  `json:"request"`
	Response httpclient.ResponseRecord `json:"response"`
}

type ReplayStep struct {
	Role                   verification.ObservationRole `json:"role"`
	IdentityID             string                       `json:"identity_id,omitempty"`
	Request                httpclient.RequestRecord     `json:"request"`
	ExpectedNormalizedHash string                       `json:"expected_normalized_hash"`
}

type ModuleFinding struct {
	Title       string
	VulnClass   string
	Severity    string
	Description string
	Endpoint    string
	Parameter   string
	Location    string
	Confidence  verification.ConfidenceLevel
	Evidence    Evidence
}

type EventSink func(eventType, message string, payload map[string]interface{}) error

var errDuplicateFinding = errors.New("duplicate canonical finding")

type Runner struct {
	scanID          string
	client          HTTPDoer
	scope           *scope.Engine
	db              *storage.DB
	verifier        *verification.Engine
	oast            OASTClient
	roles           RoleComparer
	authResolve     AuthProfileResolver
	browser         BrowserRenderer
	tlsInspector    TLSInspector
	websocket       WebSocketProber
	smuggling       SmugglingProber
	runtimeSensor   *sensor.Collector
	mutationGuard   *safemutation.Guard
	emit            EventSink
	cfg             config.ScanConfig
	storedMu        sync.Mutex
	stored          map[string]string
	baselineMu      sync.Mutex
	baselineCache   map[string]httpclient.RequestResponse
	secretScanMu    sync.Mutex
	secretScanCache map[string][]secretscan.Match
	sqliBaselineMu  sync.Mutex
	sqliBaselines   map[string]*sqliBaselineCacheEntry
	timingMu        sync.Mutex
	delayedTiming   []delayedTimingProbe
	noticeMu        sync.Mutex
	notices         map[string]struct{}
	oastBlocked     bool
	tlsMu           sync.Mutex
	tlsReported     map[string]struct{}
	moduleSeenMu    sync.Mutex
	moduleSeen      map[string]struct{}
	findingMu       sync.Mutex
	findingSeen     map[string]int64
	budgetExhausted atomic.Bool
	probeCount      atomic.Int64
	executionErrors atomic.Int64
	categoryBudgets map[string]int64
	categoryUsage   map[string]*atomic.Int64
	rolloverPool    atomic.Int64
}

// ProbeCount reports vulnerability-module probe attempts independently from
// crawler and bootstrap traffic, so the CLI can show real payload progress.
func (r *Runner) ProbeCount() int64 {
	if r == nil {
		return 0
	}
	return r.probeCount.Load()
}

func NewRunner(scanID string, client HTTPDoer, scopeEngine *scope.Engine, db *storage.DB,
	verifier *verification.Engine, oastClient OASTClient, emit EventSink, cfg config.ScanConfig, opts ...RunnerOption) *Runner {
	r := &Runner{
		scanID: scanID, client: client, scope: scopeEngine, db: db,
		verifier: verifier, oast: oastClient, emit: emit, cfg: cfg,
		stored:          make(map[string]string),
		baselineCache:   make(map[string]httpclient.RequestResponse),
		secretScanCache: make(map[string][]secretscan.Match),
		sqliBaselines:   make(map[string]*sqliBaselineCacheEntry),
		notices:         make(map[string]struct{}),
		tlsReported:     make(map[string]struct{}),
		moduleSeen:      make(map[string]struct{}),
		findingSeen:     make(map[string]int64),
	}
	if cfg.RequestBudget > 0 {
		r.categoryBudgets = map[string]int64{
			"injection":       int64(float64(cfg.RequestBudget) * 0.35),
			"serverside":      int64(float64(cfg.RequestBudget) * 0.25),
			"logic_auth":      int64(float64(cfg.RequestBudget) * 0.25),
			"client_exposure": int64(float64(cfg.RequestBudget) * 0.15),
		}
		r.categoryUsage = map[string]*atomic.Int64{
			"injection":       new(atomic.Int64),
			"serverside":      new(atomic.Int64),
			"logic_auth":      new(atomic.Int64),
			"client_exposure": new(atomic.Int64),
		}
	}
	r.tlsInspector = newNetworkTLSInspector(cfg)
	r.websocket = newNetworkWebSocketProber(cfg, scopeEngine)
	r.smuggling = newNetworkSmugglingProber(cfg, scopeEngine)
	r.mutationGuard = safemutation.NewGuardWithFailureSink(safemutation.DefaultPolicy(),
		func(tx safemutation.Transaction, err error) {
			if r.emit != nil {
				_ = r.emit("mutation_cleanup_failed", err.Error(), map[string]interface{}{
					"operation_id": tx.OperationID, "resource_id": tx.ResourceID,
					"canary": tx.Canary, "state_before_hash": tx.StateBeforeHash,
					"state_after_hash": tx.StateAfterHash,
				})
			}
		})
	for _, opt := range opts {
		opt(r)
	}
	r.loadStoredMarkers()
	r.loadExistingFindingKeys()
	return r
}

func moduleCategory(module string) string {
	switch module {
	case "sqli", "command_injection", "ssti", "nosql":
		return "injection"
	case "ssrf", "xxe", "insecure_deserialization", "lfi", "file_upload":
		return "serverside"
	case "idor", "auth_bypass", "cors", "csrf", "broken_auth", "jwt", "oauth", "bfla", "session_fixation", "open_redirect":
		return "logic_auth"
	default:
		return "client_exposure"
	}
}

func (r *Runner) canModuleProbe(module string) bool {
	if r == nil || r.cfg.RequestBudget <= 0 {
		return true
	}
	if r.budgetExhausted.Load() {
		return false
	}
	cat := moduleCategory(module)
	usage := r.categoryUsage[cat]
	if usage == nil {
		return true
	}
	used := usage.Load()
	allocated := r.categoryBudgets[cat]
	if used < allocated {
		return true
	}
	if r.rolloverPool.Load() > 0 {
		return true
	}
	return false
}

func (r *Runner) recordModuleProbeUsage(module string) {
	if r == nil || r.cfg.RequestBudget <= 0 {
		return
	}
	cat := moduleCategory(module)
	usage := r.categoryUsage[cat]
	if usage == nil {
		return
	}
	allocated := r.categoryBudgets[cat]
	cur := usage.Add(1)
	if cur > allocated {
		r.rolloverPool.Add(-1)
	}
}

func (r *Runner) releaseUnusedCategoryBudget(cat string) {
	if r == nil || r.cfg.RequestBudget <= 0 {
		return
	}
	usage := r.categoryUsage[cat]
	if usage == nil {
		return
	}
	used := usage.Load()
	allocated := r.categoryBudgets[cat]
	if remaining := allocated - used; remaining > 0 {
		if usage.CompareAndSwap(used, allocated) {
			r.rolloverPool.Add(remaining)
		}
	}
}

func (r *Runner) loadStoredMarkers() {
	if r.db == nil || !r.cfg.EnableSecondOrderTracking {
		return
	}
	markers, err := r.db.ListSecondOrderMarkers(r.scanID)
	if err != nil {
		r.emitOnce("second_order_marker_load_failed", "coverage_gap", "Second-order stored marker cache could not be loaded", map[string]interface{}{
			"scan_id": r.scanID, "error": err.Error(),
		})
		return
	}
	if len(markers) == 0 {
		return
	}
	r.storedMu.Lock()
	defer r.storedMu.Unlock()
	for _, marker := range markers {
		if marker.EndpointURL == "" || marker.Parameter == "" || marker.Marker == "" {
			continue
		}
		r.stored[marker.EndpointURL+"::"+marker.Parameter] = marker.Marker
	}
}

func (r *Runner) loadExistingFindingKeys() {
	if r.db == nil || r.scanID == "" {
		return
	}
	_ = r.db.IterateFindings(r.scanID, func(rec storage.FindingRecord) error {
		f := ModuleFinding{
			Title: rec.Title, VulnClass: rec.VulnClass, Endpoint: rec.EndpointURL, Parameter: rec.Parameter,
		}
		if rec.EvidenceJSON != "" {
			_ = json.Unmarshal([]byte(rec.EvidenceJSON), &f.Evidence)
		}
		key := r.findingKey(f)
		if key == "" {
			return nil
		}
		r.findingMu.Lock()
		if r.findingSeen == nil {
			r.findingSeen = make(map[string]int64)
		}
		r.findingSeen[key] = rec.ID
		r.findingMu.Unlock()
		return nil
	})
}

var (
	routeNumSegmentRe  = regexp.MustCompile(`^(\d+|[0-9a-fA-F]{8,})$`)
	routeUUIDSegmentRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

func normalizeRoutePattern(path string) string {
	if path == "" || path == "/" {
		return path
	}
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		if seg == "" {
			continue
		}
		if routeUUIDSegmentRe.MatchString(seg) {
			segments[i] = "{uuid}"
		} else if routeNumSegmentRe.MatchString(seg) {
			segments[i] = "{id}"
		}
	}
	return strings.Join(segments, "/")
}

// endpointModuleOnce prevents endpoint-level modules from running once per
// discovered parameter. Query values are excluded because these modules act on
// the route/resource, not on an individual injection surface.
func (r *Runner) endpointModuleOnce(module string, target ScanTarget) bool {
	raw := target.EndpointURL
	if parsed, err := url.Parse(raw); err == nil {
		if originScopedModule(module) {
			raw = parsed.Scheme + "://" + parsed.Host
		} else if module == "cors" {
			parsed.RawQuery = ""
			parsed.Fragment = ""
			raw = parsed.Scheme + "://" + parsed.Host + normalizeRoutePattern(parsed.Path)
		} else {
			parsed.RawQuery = ""
			parsed.Fragment = ""
			raw = parsed.String()
		}
	}
	key := module + "::" + strings.ToUpper(strings.TrimSpace(target.Method)) + "::" + raw
	r.moduleSeenMu.Lock()
	defer r.moduleSeenMu.Unlock()
	if _, exists := r.moduleSeen[key]; exists {
		return false
	}
	r.moduleSeen[key] = struct{}{}
	return true
}

// contentModuleOnce prevents passive response analyzers from re-reading and
// re-scanning the same concrete URL for every discovered parameter surface.
func (r *Runner) contentModuleOnce(module string, target ScanTarget) bool {
	raw := target.EndpointURL
	if parsed, err := url.Parse(raw); err == nil {
		parsed.Fragment = ""
		raw = parsed.String()
	}
	key := module + "::" + strings.ToUpper(strings.TrimSpace(target.Method)) + "::" + raw
	r.moduleSeenMu.Lock()
	defer r.moduleSeenMu.Unlock()
	if _, exists := r.moduleSeen[key]; exists {
		return false
	}
	r.moduleSeen[key] = struct{}{}
	return true
}

func originScopedModule(module string) bool {
	switch module {
	case "actuator", "devops_exposure", "backup_archives", "security_headers", "tls_misconfig", "cloud_takeover",
		"iis_discovery", "firebase_misconfig", "spring_cloud_jolokia", "saas_exposure", "grpc_scan",
		"cicd_exposure", "git_recovery", "source_code_disclosure", "cloud_storage", "cloud_posture",
		"cloud_native_exposure", "host_poisoning", "wordpress_fuzz", "nginx_alias",
		"nextjs_bypass", "framework_debug", "cpdos", "proxy_path_confusion", "ws_cswsh", "react_rsc_rce",
		"swagger_exposure", "sensitive_file_discovery", "http_smuggling", "debug_admin",
		"vulnerable_components", "known_cve", "cors_oast":
		return true
	default:
		return false
	}
}

func originScanTarget(target ScanTarget) (ScanTarget, bool) {
	parsed, err := url.Parse(target.EndpointURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ScanTarget{}, false
	}
	target.EndpointURL = parsed.Scheme + "://" + parsed.Host
	target.Method = "GET"
	target.Parameter = ""
	target.Location = ""
	target.BodyTemplate = ""
	target.RequestTemplate = reflection.RequestTemplate{}
	return target, true
}

func (r *Runner) safeMutationGuard() *safemutation.Guard {
	if r.mutationGuard == nil {
		r.mutationGuard = safemutation.NewGuard(safemutation.DefaultPolicy())
	}
	return r.mutationGuard
}

func (r *Runner) emitOnce(key, eventType, message string, payload map[string]interface{}) {
	r.noticeMu.Lock()
	if _, exists := r.notices[key]; exists {
		r.noticeMu.Unlock()
		return
	}
	r.notices[key] = struct{}{}
	r.noticeMu.Unlock()
	if r.emit != nil {
		_ = r.emit(eventType, message, payload)
	}
}

func (r *Runner) oastDeliveryBlocked() bool {
	r.noticeMu.Lock()
	defer r.noticeMu.Unlock()
	return r.oastBlocked
}

func (r *Runner) blockOASTDelivery() {
	r.noticeMu.Lock()
	r.oastBlocked = true
	r.noticeMu.Unlock()
}

type RunnerOption func(*Runner)

func WithRoleComparer(rc RoleComparer) RunnerOption {
	return func(r *Runner) { r.roles = rc }
}

func WithAuthResolver(ar AuthProfileResolver) RunnerOption {
	return func(r *Runner) { r.authResolve = ar }
}

func WithBrowserRenderer(browser BrowserRenderer) RunnerOption {
	return func(r *Runner) { r.browser = browser }
}

func WithTLSInspector(inspector TLSInspector) RunnerOption {
	return func(r *Runner) { r.tlsInspector = inspector }
}

func WithWebSocketProber(prober WebSocketProber) RunnerOption {
	return func(r *Runner) { r.websocket = prober }
}

func WithSmugglingProber(prober SmugglingProber) RunnerOption {
	return func(r *Runner) { r.smuggling = prober }
}

func WithRuntimeSensor(collector *sensor.Collector) RunnerOption {
	return func(r *Runner) { r.runtimeSensor = collector }
}

func (r *Runner) RunGroupA(ctx context.Context, targets []ScanTarget) ([]ModuleFinding, error) {
	_ = r.emit("vuln_modules_started", "Injection vulnerability scanning started", map[string]interface{}{
		"scan_id": r.scanID, "targets": len(targets),
	})

	workers := r.cfg.PerHostConcurrency
	if workers <= 0 {
		workers = 8
	}
	if workers > len(targets) {
		workers = len(targets)
	}

	var mu sync.Mutex
	var findings []ModuleFinding
	var testedCount atomic.Int64
	var skippedBudgetCount atomic.Int64

	targetCh := make(chan ScanTarget, moduleQueueCapacity(workers, len(targets)))

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if rec := recover(); rec != nil {
					_ = r.emit("log", fmt.Sprintf("RunGroupA worker recovered from panic: %v", rec), map[string]interface{}{"scan_id": r.scanID})
				}
			}()
			for target := range targetCh {
				if ctx.Err() != nil {
					return
				}
				if r.budgetExhausted.Load() || !r.canModuleProbe("sqli") {
					skippedBudgetCount.Add(1)
					continue
				}
				if !r.scope.IsInScope(target.EndpointURL) {
					continue
				}
				testedCount.Add(1)
				func() {
					defer func() {
						if rec := recover(); rec != nil {
							_ = r.emit("log", fmt.Sprintf("RunGroupA target %s recovered from panic: %v", target.EndpointURL, rec), map[string]interface{}{"scan_id": r.scanID})
						}
					}()
					var localFindings []ModuleFinding
					if r.cfg.AllowsModule("xss") {
						localFindings = append(localFindings, r.runXSS(ctx, target)...)
					}
					if r.cfg.AllowsModule("blind_xss") {
						localFindings = append(localFindings, r.runBlindXSS(ctx, target)...)
					}
					if r.cfg.AllowsModule("sqli") {
						localFindings = append(localFindings, r.runSQLi(ctx, target)...)
					}
					if r.cfg.AllowsModule("nosql") {
						localFindings = append(localFindings, r.runNoSQLi(ctx, target)...)
					}
					if r.cfg.AllowsModule("ssti") {
						localFindings = append(localFindings, r.runSSTI(ctx, target)...)
					}
					if r.cfg.AllowsModule("command_injection") {
						localFindings = append(localFindings, r.runCommandInjection(ctx, target)...)
					}

					if len(localFindings) > 0 {
						mu.Lock()
						findings = append(findings, localFindings...)
						mu.Unlock()
					}
				}()
			}
		}()
	}
	feedModuleTargets(ctx, targetCh, targets)
	wg.Wait()

	r.releaseUnusedCategoryBudget("injection")
	totalTargets := len(targets)
	tested := int(testedCount.Load())
	skipped := int(skippedBudgetCount.Load())
	coveragePct := 100.0
	if totalTargets > 0 {
		coveragePct = float64(tested) / float64(totalTargets) * 100.0
	}
	_ = r.emit("vuln_modules_finished", "Injection vulnerability scanning finished", map[string]interface{}{
		"scan_id": r.scanID, "findings": len(findings),
		"targets_tested": tested, "targets_total": totalTargets,
		"coverage_percentage": fmt.Sprintf("%.1f%%", coveragePct),
	})
	if skipped > 0 {
		r.emitOnce("group_budget_starved:group_a", "coverage_gap",
			fmt.Sprintf("Injection scan group was budget-starved: tested %d of %d targets (%.1f%% coverage)", tested, totalTargets, coveragePct),
			map[string]interface{}{
				"scan_id": r.scanID, "group": "group_a",
				"targets_tested": tested, "targets_total": totalTargets,
				"coverage_pct": coveragePct,
			},
		)
	}
	findings = append(findings, r.flushDelayedTimingVerifications(ctx)...)
	return findings, nil
}

// moduleQueueCapacity keeps large target sets from being duplicated in a
// channel buffer. The source slice is already resident; only a small working
// set needs to be queued for active workers.
func moduleQueueCapacity(workers, targets int) int {
	capacity := workers * 2
	if capacity < 1 {
		capacity = 1
	}
	if capacity > 256 {
		capacity = 256
	}
	if targets > 0 && capacity > targets {
		capacity = targets
	}
	return capacity
}

func feedModuleTargets(ctx context.Context, targetCh chan<- ScanTarget, targets []ScanTarget) {
	defer close(targetCh)
	for _, target := range targets {
		select {
		case targetCh <- target:
		case <-ctx.Done():
			return
		}
	}
}

func (r *Runner) persistFinding(f ModuleFinding, eventContext ...string) error {
	if r.db == nil || f.Confidence == verification.Suppressed || !findingProofEligible(f) {
		return nil
	}
	if f.Confidence == verification.Confirmed {
		r.recordLearning(f.Endpoint, f.VulnClass, learning.OutcomeWorked)
	}
	ev, _ := json.Marshal(f.Evidence)
	evJSON := string(ev)
	key, existingID, duplicate := r.claimFinding(f)
	if duplicate {
		if existingID > 0 {
			_ = r.db.SaveEvidenceForFinding(r.scanID, existingID, f.VulnClass+"_variant_signal", evJSON)
			_ = r.saveVerificationObservations(existingID, f)
		}
		return errDuplicateFinding
	}
	desc := f.Description + "\n\nevidence: " + evJSON
	conf := f.Evidence.Verification.Score
	if conf <= 0 {
		conf = confidenceScore(f.Confidence)
	}
	findingID, err := r.db.SaveFinding(r.scanID, f.Title, f.Severity, f.VulnClass, desc, f.Endpoint, f.Parameter, conf, evJSON)
	if err != nil {
		r.releaseFindingKey(key)
		return err
	}
	r.finishFindingKey(key, findingID)
	module := f.Evidence.Module
	signal := f.Evidence.Signal
	if len(eventContext) > 0 && eventContext[0] != "" {
		module = eventContext[0]
	}
	if len(eventContext) > 1 && eventContext[1] != "" {
		signal = eventContext[1]
	}
	r.emitFindingDetected(f, module, signal, findingID)
	if err := r.db.SaveEvidenceForFinding(r.scanID, findingID, f.VulnClass+"_signal", evJSON); err != nil {
		return err
	}
	if err := r.saveVerificationObservations(findingID, f); err != nil {
		return err
	}
	return nil
}

func (r *Runner) claimFinding(f ModuleFinding) (string, int64, bool) {
	key := r.findingKey(f)
	if key == "" {
		return "", 0, false
	}
	r.findingMu.Lock()
	defer r.findingMu.Unlock()
	if r.findingSeen == nil {
		r.findingSeen = make(map[string]int64)
	}
	if existingID, exists := r.findingSeen[key]; exists {
		return key, existingID, true
	}
	r.findingSeen[key] = 0
	return key, 0, false
}

func (r *Runner) finishFindingKey(key string, findingID int64) {
	if key == "" {
		return
	}
	r.findingMu.Lock()
	if r.findingSeen == nil {
		r.findingSeen = make(map[string]int64)
	}
	r.findingSeen[key] = findingID
	r.findingMu.Unlock()
}

func (r *Runner) releaseFindingKey(key string) {
	if key == "" {
		return
	}
	r.findingMu.Lock()
	delete(r.findingSeen, key)
	r.findingMu.Unlock()
}

func (r *Runner) saveVerificationObservations(findingID int64, f ModuleFinding) error {
	for _, observation := range f.Evidence.Verification.Observations {
		record := storage.VerificationObservationRecord{
			ID: observation.ID, FindingID: findingID, ScanID: observation.ScanID,
			Module: observation.Module, Endpoint: observation.Endpoint, Parameter: observation.Parameter,
			Location: observation.Location, Role: string(observation.Role), Attempt: observation.Attempt,
			IdentityID: observation.IdentityID, RequestID: observation.RequestID,
			RequestMethod: observation.RequestMethod, RequestURL: observation.RequestURL,
			RequestHash: observation.RequestHash, ResponseHash: observation.ResponseHash,
			NormalizedHash: observation.NormalizedHash, StatusCode: observation.StatusCode,
			ContentType: observation.ContentType, DurationMs: observation.DurationMs,
			StateBeforeHash: observation.StateBeforeHash, StateAfterHash: observation.StateAfterHash,
			OASTPayloadID: observation.OASTPayloadID, RuntimeTraceID: observation.RuntimeTraceID,
			RuntimeSink: observation.RuntimeSink, RuntimeSafe: observation.RuntimeSafe,
			CreatedAt: observation.CreatedAt,
		}
		if err := r.db.SaveVerificationObservation(findingID, record); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runner) findingKey(f ModuleFinding) string {
	module := strings.ToLower(strings.TrimSpace(f.Evidence.Module))
	if module == "" {
		module = strings.ToLower(strings.TrimSpace(f.VulnClass))
	}
	if module == "" {
		module = strings.ToLower(strings.TrimSpace(f.Title))
	}
	endpoint := canonicalFindingEndpoint(f.Endpoint)
	if endpoint == "" && f.Evidence.Request.URL != "" {
		endpoint = canonicalFindingEndpoint(f.Evidence.Request.URL)
	}
	if endpoint == "" {
		return ""
	}
	method := strings.ToUpper(strings.TrimSpace(f.Evidence.Request.Method))
	if method == "" {
		method = "GET"
	}
	parameter := strings.ToLower(strings.TrimSpace(f.Parameter))
	if parameter == "" {
		parameter = strings.ToLower(strings.TrimSpace(f.Evidence.Parameter))
	}
	location := strings.ToLower(strings.TrimSpace(f.Location))
	if location == "" {
		location = strings.ToLower(strings.TrimSpace(f.Evidence.Location))
	}
	if module == "security_headers" || module == "tls_misconfig" {
		if u, err := url.Parse(endpoint); err == nil && u.Scheme != "" && u.Host != "" {
			endpoint = u.Scheme + "://" + u.Host
		}
		parameter = ""
	}
	if module == "cookie_security" {
		if u, err := url.Parse(endpoint); err == nil && u.Scheme != "" && u.Host != "" {
			endpoint = u.Scheme + "://" + u.Host
		}
		if parameter == "" && f.Evidence.Payload.Value != "" {
			parameter = strings.ToLower(f.Evidence.Payload.Value)
		}
	}
	signal := strings.ToLower(strings.TrimSpace(f.Evidence.Signal))
	if collapsePayloadVariants(module, parameter) {
		signal = ""
	}
	return strings.Join([]string{r.scanID, module, method, endpoint, parameter, location, signal}, "\x1f")
}

func collapsePayloadVariants(module, parameter string) bool {
	if strings.TrimSpace(parameter) == "" {
		return false
	}
	return module != ""
}

func canonicalFindingEndpoint(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return strings.TrimSpace(raw)
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	parsed.Fragment = ""
	if parsed.RawQuery != "" {
		parsed.RawQuery = parsed.Query().Encode()
	}
	return parsed.String()
}

func (r *Runner) recordLearning(endpointURL, family string, outcome learning.Outcome) {
	if r.db == nil || endpointURL == "" || family == "" {
		return
	}
	host := hostFromModuleURL(endpointURL)
	if host == "" {
		return
	}
	store := learning.NewStore(r.db)
	_ = store.RecordOutcome(host, endpointURL, family, outcome)
	_ = store.RecordOutcome(host, "", family, outcome)
}

func confidenceScore(level verification.ConfidenceLevel) float64 {
	switch level {
	case verification.Confirmed:
		return 0.95
	case verification.HighConfidence:
		return 0.8
	case verification.Potential:
		return 0.6
	default:
		return 0.45
	}
}
