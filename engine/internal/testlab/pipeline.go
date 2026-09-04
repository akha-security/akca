package testlab

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/browserpool"
	"github.com/akha-security/akca/engine/internal/bypass403"
	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/crawler"
	"github.com/akha-security/akca/engine/internal/events"
	"github.com/akha-security/akca/engine/internal/evidencestore"
	"github.com/akha-security/akca/engine/internal/fuzzing"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/jsanalyzer"
	"github.com/akha-security/akca/engine/internal/models"
	"github.com/akha-security/akca/engine/internal/modules"
	"github.com/akha-security/akca/engine/internal/oast"
	"github.com/akha-security/akca/engine/internal/params"
	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/queue"
	"github.com/akha-security/akca/engine/internal/ratelimit"
	"github.com/akha-security/akca/engine/internal/reflection"
	"github.com/akha-security/akca/engine/internal/report"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/verification"
	"github.com/akha-security/akca/engine/internal/waf"
	"github.com/akha-security/akca/engine/internal/wafintel"
)

type pipeline struct {
	scanID           string
	short            bool
	cfg              config.ScanConfig
	client           *httpclient.Client
	scope            *scope.Engine
	db               *storage.DB
	emit             func(string, string, map[string]interface{}) error
	lab              *Server
	transport        *LabTransport
	queue403         *fuzzing.Queue403
	oast             *oast.Listener
	verifier         *verification.Engine
	runnerOpts       []modules.RunnerOption
	capabilities     map[string]bool
	parityCorpusSize int
	enableAuth       bool
	enableAuthParity bool
}

func runPipeline(ctx context.Context, db *storage.DB, opts Options, collector *EventCollector) (Result, error) {
	backend, err := url.Parse(opts.Lab.Server.URL)
	if err != nil {
		return Result{}, err
	}
	transport := NewLabTransport(DefaultDomain, backend)
	cfg := labScanConfig(opts.Short)
	cfg.ScanID = opts.ScanID
	cfg.Targets = []string{opts.Lab.BaseURL(), "http://" + DefaultDomain + "/"}
	cfg.IncludeDomains = []string{opts.Lab.ScopeDomain(), DefaultDomain}
	cfg.ExcludeDomains = []string{"offscope.evil", "evil.example"}
	cfg.TestRoundTripper = transport
	cfg.EnableOAST = opts.EnableOAST
	if opts.EnableOAST {
		cfg.OASTPollInterval = 10 * time.Millisecond
	}
	if opts.EnableAuth {
		cfg.SessionCookies = map[string]string{"akca_session": "valid"}
	}
	if opts.EnableAuthParity {
		if cfg.CustomHeaders == nil {
			cfg.CustomHeaders = map[string]string{}
		}
		cfg.CustomHeaders["Authorization"] = "Bearer " + LabValidJWT()
		cfg.JWTExpiredTokens = []string{LabExpiredJWT()}
		cfg.KnownAccounts = []string{"known@example.com"}
		cfg.RateLimitPolicies = []config.RateLimitPolicy{{
			URLContains: "/parity/auth/login", Account: "known@example.com",
			Threshold: 3, CooldownSeconds: 1, PerAccount: true,
		}}
	}
	if opts.RequestBudget > 0 {
		cfg.RequestBudget = opts.RequestBudget
	}

	runCtx, cancel := context.WithTimeout(ctx, cfg.TimeBudget)
	defer cancel()

	scopeEngine := scope.NewEngine(cfg)
	limiter := ratelimit.New(cfg.GlobalRateLimit, cfg.PerHostRateLimit)
	client, err := httpclient.New(cfg, scopeEngine, limiter)
	if err != nil {
		return Result{}, err
	}

	batcher := events.NewBatcher(collector, 50, 100*time.Millisecond)
	defer func() { _ = batcher.Close() }()

	emit := func(eventType, message string, payload map[string]interface{}) error {
		return batcher.Emit(events.Event{Type: eventType, Message: message, Payload: payload})
	}

	_ = db.EnsureScan(cfg.ScanID)
	_ = emit("scan_started", "integration scan started", map[string]interface{}{"scan_id": cfg.ScanID, "targets": cfg.Targets})

	var oastListener *oast.Listener
	if cfg.EnableOAST {
		oastListener, err = oast.NewListener(db, emit, oast.Config{PollInterval: cfg.OASTPollInterval})
		if err != nil {
			return Result{}, err
		}
		_ = oastListener.Start(runCtx)
		defer oastListener.Stop()
		oastListener.SetScanID(cfg.ScanID)
		if local, ok := oastListener.Provider().(*oast.LocalProvider); ok {
			domain := strings.ToLower(local.Domain())
			opts.Lab.SetOASTInteractionSink(func(host string) {
				host = strings.ToLower(strings.TrimSpace(host))
				if strings.HasSuffix(host, "."+domain) {
					local.InjectInteraction(strings.TrimSuffix(host, "."+domain), "http", "127.0.0.1")
				}
			})
			defer opts.Lab.SetOASTInteractionSink(nil)
		}
	}

	capabilities := map[string]bool{
		"auth": opts.EnableAuth, "auth_parity": opts.EnableAuthParity, "oast": oastListener != nil,
	}
	var runnerOpts []modules.RunnerOption
	if opts.EnableBrowser {
		renderer := browserpool.NewHeadlessRenderer()
		if renderer.Available() {
			smokeCtx, smokeCancel := context.WithTimeout(runCtx, 5*time.Second)
			rendered, smokeErr := renderer.Render(smokeCtx,
				"data:text/html,<script>document.documentElement.setAttribute('data-akca-xss','executed')</script>")
			smokeCancel()
			if smokeErr == nil && verification.CheckDOMExecution(rendered) {
				runnerOpts = append(runnerOpts, modules.WithBrowserRenderer(renderer))
				capabilities["browser"] = true
			}
		}
	}
	p := &pipeline{
		scanID: cfg.ScanID, short: opts.Short, cfg: cfg, client: client, scope: scopeEngine, db: db,
		emit: emit, lab: opts.Lab, transport: transport, oast: oastListener,
		verifier:   verification.NewEngine(db, emit),
		runnerOpts: runnerOpts, capabilities: capabilities,
		parityCorpusSize: opts.ParityCorpusSize, enableAuth: opts.EnableAuth,
		enableAuthParity: opts.EnableAuthParity,
	}

	if err := p.run(runCtx); err != nil {
		return Result{}, err
	}

	metrics, err := db.DashboardMetrics(opts.ScanID)
	if err != nil {
		return Result{}, err
	}
	findings, err := db.ListFindings(opts.ScanID, 5000, 0)
	if err != nil {
		return Result{}, err
	}

	reports, reportSchemaCompatible, err := p.generateReports()
	if err != nil {
		return Result{}, err
	}

	_ = emit("scan_finished", "integration scan finished", map[string]interface{}{"scan_id": cfg.ScanID})

	return Result{
		ScanID:                 opts.ScanID,
		Events:                 collector,
		Metrics:                metrics,
		Findings:               findings,
		RequestCount:           transport.RequestCount(),
		Reports:                reports,
		Capabilities:           capabilities,
		ReportSchemaCompatible: reportSchemaCompatible,
	}, nil
}

func (p *pipeline) run(ctx context.Context) error {
	targets := []string{p.lab.BaseURL()}

	_ = p.emit("phase_started", "fingerprinting", map[string]interface{}{"phase": "fingerprinting"})
	if p.cfg.EnableWAFDetection {
		prof := waf.NewProfiler(p.client)
		for _, target := range targets {
			profile, err := prof.Profile(ctx, target)
			if err == nil && profile.Vendor != "" {
				_ = p.db.SaveWAFProfile(p.scanID, profile)
				_ = p.emit("waf_detected", profile.Vendor, map[string]interface{}{"host": profile.Host, "vendor": profile.Vendor})
			}
		}
	} else {
		host := p.lab.ScopeDomain()
		_ = p.db.SaveWAFProfile(p.scanID, models.WAFProfile{Host: host, Vendor: "Cloudflare", CDN: "Cloudflare", Confidence: 0.9})
	}
	_ = p.emit("phase_finished", "fingerprinting", map[string]interface{}{"phase": "fingerprinting"})

	_ = p.emit("phase_started", "learning_waf", map[string]interface{}{"phase": "learning_waf"})
	_ = wafintel.NewRunner(p.scanID, p.db, p.emit).Calibrate(ctx, []string{p.lab.BaseURL()})
	_ = p.emit("phase_finished", "learning_waf", map[string]interface{}{"phase": "learning_waf"})

	c := crawler.New(p.scanID, p.cfg, p.client, p.scope, p.db, p.emit)
	_ = p.emit("phase_started", "crawling", map[string]interface{}{"phase": "crawling"})
	if err := c.Crawl(ctx, targets); err != nil {
		return err
	}
	_ = p.emit("phase_finished", "crawling", map[string]interface{}{"phase": "crawling"})

	_ = p.db.SaveDiscoveredEndpoint(p.scanID, crawler.DiscoveredEndpoint{
		URL: p.lab.Server.URL + "/graphql", Method: "POST", NormalizedURL: p.lab.Server.URL + "/graphql",
		Source: "integration_seed", Confidence: 1, WhyDiscovered: "lab graphql seed",
	})

	if p.cfg.EnableJSAnalysis {
		reqQ := queue.NewRequestQueue()
		jsa := jsanalyzer.New(p.scanID, p.client, p.scope, p.db, reqQ, p.emit)
		_, _ = jsa.DownloadAndAnalyze(ctx, p.lab.Server.URL+"/static/app.js")
	}

	d := params.NewDiscoverer(p.scanID, p.client, p.scope, p.db, p.emit)
	// Keep the integration pipeline aligned with the production app. Leaving
	// discovery unlimited lets it consume the global request budget before the
	// Group B modules (SSRF/XXE/open redirect) execute.
	d.SetMaxProbes(p.cfg.ParameterMaxProbes())
	d.SetWordlistCap(p.cfg.ParameterWordlistCap())
	d.SetMaxTransferProbes(p.cfg.ParameterTransferMaxProbes())
	d.SetParallelism(p.cfg.ParameterDiscoveryWorkers())
	_ = p.emit("phase_started", "parameter_discovery", map[string]interface{}{"phase": "parameter_discovery"})
	if p.short {
		p.seedLabParameters()
	} else if err := d.Run(ctx, 10); err != nil {
		return err
	}
	_ = p.emit("phase_finished", "parameter_discovery", map[string]interface{}{"phase": "parameter_discovery"})

	p.seedLabParameters()

	if p.cfg.EnableFuzzing {
		workers := p.cfg.MaxConcurrency
		if workers <= 0 {
			workers = 2
		}
		fe := fuzzing.NewEngine(p.scanID, p.client, p.scope, p.db, p.emit, workers)
		p.queue403 = fe.Queue403()
		_ = p.emit("phase_started", "fuzzing", map[string]interface{}{"phase": "fuzzing"})
		tasks := fuzzing.BuildIntegrationTasks(p.lab.BaseURL())
		if err := fe.RunTasks(ctx, tasks); err != nil {
			return err
		}
		_ = p.emit("phase_finished", "fuzzing", map[string]interface{}{"phase": "fuzzing"})
	} else {
		p.queue403 = fuzzing.NewQueue403(32)
		_ = p.db.SaveDiscoveredEndpoint(p.scanID, crawler.DiscoveredEndpoint{
			URL: p.lab.Server.URL + "/admin", Method: "GET", NormalizedURL: p.lab.Server.URL + "/admin",
			Source: "integration_seed", Confidence: 1, WhyDiscovered: "lab admin seed",
		})
		p.queue403.Enqueue(p.lab.Server.URL+"/admin", "GET")
	}

	if p.cfg.Enable403BypassChecks && p.queue403 != nil {
		be := bypass403.NewEngine(p.scanID, p.client, p.scope, p.db, p.queue403, p.emit, 2)
		_ = p.emit("phase_started", "bypass403", map[string]interface{}{"phase": "bypass403"})
		if err := be.Run(ctx); err != nil {
			return err
		}
		_ = p.emit("phase_finished", "bypass403", map[string]interface{}{"phase": "bypass403"})
	}

	ra := reflection.NewAnalyzer(p.scanID, p.client, p.scope, p.db, p.emit)
	if p.cfg.RequestBudget > 0 && p.cfg.RequestBudget < 60 {
		ra.SetMaxParams(p.cfg.RequestBudget / 2)
	}
	if p.short {
		ra.SetMaxParams(8)
	}
	_ = p.emit("phase_started", "reflection", map[string]interface{}{"phase": "reflection"})
	profileLimit := 12
	if p.short {
		profileLimit = 8
	}
	profiles, err := ra.Run(ctx, profileLimit)
	if err != nil {
		return err
	}
	pg := payloadgen.NewGenerator(p.scanID, p.db, p.cfg, p.emit)
	if _, err := pg.Run(ctx, profiles); err != nil {
		return err
	}
	_ = p.emit("phase_finished", "reflection", map[string]interface{}{"phase": "reflection", "profiles": len(profiles)})

	var oastClient modules.OASTClient
	if p.oast != nil {
		oastClient = p.oast
	}
	runner := modules.NewRunner(p.scanID, p.client, p.scope, p.db, p.verifier, oastClient, p.emit, p.cfg, p.runnerOpts...)
	_ = p.emit("phase_started", "vuln_modules_subset", map[string]interface{}{"phase": "vuln_modules_subset"})
	moduleTargets := p.labModuleTargets(runner)
	if _, err := runner.RunIntegrationSubset(ctx, moduleTargets); err != nil {
		return err
	}
	if p.enableAuth {
		authCfg := p.cfg
		authCfg.AllowedVulnerabilityClasses = []string{"broken_auth"}
		authRunner := modules.NewRunner(p.scanID, p.client, p.scope, p.db, p.verifier, oastClient, p.emit, authCfg, p.runnerOpts...)
		authTarget := modules.ScanTarget{EndpointURL: strings.TrimRight(p.lab.Server.URL, "/") + "/auth/profile", Method: "GET"}
		if _, err := authRunner.RunGroupC(ctx, []modules.ScanTarget{authTarget}); err != nil {
			return err
		}
	}
	if p.enableAuthParity {
		base := strings.TrimRight(p.lab.Server.URL, "/")
		authTargets := []struct {
			module string
			target modules.ScanTarget
		}{
			{"jwt", modules.ScanTarget{EndpointURL: base + "/parity/auth/jwt", Method: "GET"}},
			{"oauth", modules.ScanTarget{
				EndpointURL: base + "/parity/oauth/authorize?client_id=akca&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&state=akca-state&response_type=code",
				Method:      "GET", Parameter: "redirect_uri", Location: "query",
			}},
			{"account_enum", modules.ScanTarget{
				EndpointURL: base + "/parity/auth/forgot", Method: "GET", Parameter: "email", Location: "query",
			}},
			{"rate_limit", modules.ScanTarget{
				EndpointURL: base + "/parity/auth/login", Method: "GET", Parameter: "username", Location: "query",
			}},
			{"mass_assignment", modules.ScanTarget{
				EndpointURL: base + "/parity/api/profile", Method: "PATCH", Parameter: "body", Location: "json",
				BodyTemplate: `{"name":"alice","role":"user"}`,
				Profile:      reflection.ReflectionProfile{ContentType: "application/json"},
			}},
		}
		for _, item := range authTargets {
			moduleCfg := p.cfg
			moduleCfg.AllowedVulnerabilityClasses = []string{item.module}
			moduleRunner := modules.NewRunner(p.scanID, p.client, p.scope, p.db, p.verifier, oastClient, p.emit, moduleCfg, p.runnerOpts...)
			if _, err := moduleRunner.RunGroupC(ctx, []modules.ScanTarget{item.target}); err != nil {
				return err
			}
		}
	}
	if p.oast != nil {
		p.oast.Drain(ctx, 100*time.Millisecond)
		if _, err := modules.FinalizeOASTFindings(p.db, p.scanID, p.emit); err != nil {
			return err
		}
	}
	_ = p.emit("phase_finished", "vuln_modules_subset", map[string]interface{}{"phase": "vuln_modules_subset"})

	_ = p.emit("phase_started", "report_generation", map[string]interface{}{"phase": "report_generation"})
	return nil
}

func (p *pipeline) seedLabParameters() {
	base := strings.TrimRight(p.lab.Server.URL, "/")
	seeds := []struct {
		path, method, param, location string
	}{
		{"/search", "GET", "q", "query"},
		{"/api/users", "GET", "id", "query"},
		{"/redirect", "GET", "url", "query"},
		{"/coupon/claim", "GET", "claim", "query"},
		{"/api/fetch", "GET", "url", "query"},
		{"/download", "GET", "file", "query"},
		{"/xml", "POST", "body", "body"},
		{"/waf-probe", "GET", "x", "query"},
	}
	for _, s := range seeds {
		raw := base + s.path
		_ = p.db.SaveDiscoveredEndpoint(p.scanID, crawler.DiscoveredEndpoint{
			URL: raw, Method: s.method, NormalizedURL: raw, Source: "integration_seed",
			Confidence: 1, WhyDiscovered: "lab parameter seed",
		})
		id, err := p.db.GetEndpointID(p.scanID, raw, s.method)
		if err != nil || id == 0 {
			continue
		}
		_ = p.db.SaveParameter(id, s.param, s.location, 10)
	}
}

func (p *pipeline) generateReports() (map[string]int, bool, error) {
	store := evidencestore.New(p.db)
	builder := report.NewBuilder(store, p.db)
	exporter := report.NewExporter(builder, func(report.Progress) {})
	out := map[string]int{}
	schemaCompatible := true
	for _, tmpl := range []report.TemplateKind{report.TemplateInternal, report.TemplateHackerOne, report.TemplateExecutive} {
		for _, format := range []report.Format{report.FormatJSON, report.FormatHTML, report.FormatCSV, report.FormatMarkdown} {
			opts := report.Options{ScanID: p.scanID, Template: tmpl, Format: format, Redact: false}
			var buf bytes.Buffer
			if err := exporter.Export(&buf, opts); err != nil {
				return nil, false, fmt.Errorf("%s/%s: %w", tmpl, format, err)
			}
			if format == report.FormatJSON {
				if err := report.ValidateJSONSchema(buf.Bytes()); err != nil {
					schemaCompatible = false
					return nil, false, fmt.Errorf("%s/%s schema: %w", tmpl, format, err)
				}
			}
			meta, err := builder.BuildMeta(opts)
			if err != nil {
				return nil, false, err
			}
			raw, _ := json.Marshal(meta)
			if err := store.SaveReportRecord(p.scanID, string(tmpl), string(format), "", string(raw)); err != nil {
				return nil, false, err
			}
			out[string(tmpl)+"/"+string(format)] = len(buf.Bytes())
		}
	}
	return out, schemaCompatible, nil
}
