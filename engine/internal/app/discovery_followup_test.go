package app

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/events"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/ratelimit"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/session"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/verification"
)

func TestDiscoveryFollowupScansNewInputsAndRestoresCompletedWork(t *testing.T) {
	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultScanConfig()
	cfg.ScanID = "incremental-discovery"
	cfg.Targets = []string{"https://example.test"}
	cfg.IncludeDomains = []string{"example.test"}
	cfg.AllowedVulnerabilityClasses = []string{"xss"}
	cfg.EnableOAST = false
	cfg.EnableHeadlessCrawler = false
	cfg.RequestBudget = 0
	cfg.GlobalRateLimit, cfg.PerHostRateLimit = 10000, 10000
	if err := db.EnsureScan(cfg.ScanID); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	requests := map[string]int{}
	cfg.TestRoundTripper = php2ShellTransportFunc(func(req *http.Request) (*http.Response, error) {
		mu.Lock()
		requests[req.URL.Path]++
		mu.Unlock()
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/html"}}, Body: io.NopCloser(strings.NewReader("<html><body>Search completed without reflecting supplied input.</body></html>")), Request: req}, nil
	})
	scopeEngine := scope.NewEngine(cfg)
	client, err := httpclient.New(cfg, scopeEngine, ratelimit.New(10000, 10000))
	if err != nil {
		t.Fatal(err)
	}
	batcher := events.NewBatcher(noopWriter{}, 100, time.Hour)
	defer batcher.Close()
	e := &Engine{db: db, session: session.NewScanSession(cfg), client: client, scope: scopeEngine, verifier: verification.NewEngine(db, nil), batcher: batcher}
	save := func(raw string) {
		t.Helper()
		if err := db.SaveDiscoveredEndpoint(cfg.ScanID, map[string]interface{}{"url": raw, "method": "GET", "source": "path_fuzzing", "request_template": map[string]interface{}{"method": "GET", "url": raw, "response_status": 200, "response_headers": map[string]string{"Content-Type": "text/html"}, "response_body": "<html>Observed application page</html>"}}); err != nil {
			t.Fatal(err)
		}
	}
	save("https://example.test/search?q=native")
	save("https://example.test/filter?name=native")
	if err := db.SaveDiscoveredEndpoint(cfg.ScanID, map[string]interface{}{
		"url": "https://example.test/cdn-cgi/rum", "method": "POST", "source": "browser_xhr",
		"request_template": map[string]string{"body": "{\"timing\":1}", "content_type": "application/json"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.runVulnModulesStage(context.Background(), "priority"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	initial := requests["/search"]
	filter, telemetry := requests["/filter"], requests["/cdn-cgi/rum"]
	mu.Unlock()
	if initial == 0 {
		t.Fatal("priority stage never tested the original input")
	}
	if filter == 0 || telemetry != 0 {
		t.Fatalf("XSS request distribution: search=%d filter=%d telemetry=%d", initial, filter, telemetry)
	}
	initialTargets, err := e.moduleRunner.LoadTargetsWithEndpointsFromDB(0)
	if err != nil {
		t.Fatal(err)
	}
	if pending := e.moduleRunner.PendingTargets("xss", initialTargets); len(pending) != 0 {
		t.Fatalf("priority stage left %d already assessed targets for a duplicate XSS phase", len(pending))
	}
	e.moduleRunner.Close()
	e.moduleRunner = nil // simulate restoring a checkpoint
	save("https://example.test/late?hidden=native")
	followupTargets, err := e.vulnModuleRunner().LoadTargetsWithEndpointsFromDB(0)
	if err != nil {
		t.Fatal(err)
	}
	for _, pending := range e.moduleRunner.PendingTargets("xss", followupTargets) {
		if !strings.Contains(pending.EndpointURL, "/late") {
			t.Fatalf("already assessed target was queued after restore: %+v", pending)
		}
	}
	if err := e.runVulnModulesStage(context.Background(), "followup"); err != nil {
		t.Fatal(err)
	}
	defer e.moduleRunner.Close()
	mu.Lock()
	defer mu.Unlock()
	if requests["/search"] != initial {
		t.Fatalf("completed input was tested again after resume: before=%d after=%d", initial, requests["/search"])
	}
	if requests["/late"] == 0 {
		t.Fatal("fuzz-discovered input never reached the injection module")
	}
}

func TestLaterModuleStillProbesHostWithEarlierPressure(t *testing.T) {
	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultScanConfig()
	cfg.ScanID = "late-module-pressure"
	cfg.Targets = []string{"https://example.test/"}
	cfg.AllowedVulnerabilityClasses = []string{"http_methods"}
	cfg.TestRoundTripper = php2ShellTransportFunc(func(req *http.Request) (*http.Response, error) {
		status := http.StatusOK
		if req.URL.Path == "/pressure" {
			status = 520
		}
		return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("example response")), Request: req}, nil
	})
	sc := scope.NewEngine(cfg)
	client, err := httpclient.New(cfg, sc, ratelimit.New(10000, 10000))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := client.Do(ctx, http.MethodPost, "https://example.test/pressure", nil, nil); err != nil {
		t.Fatal(err)
	}
	if !client.HostUnderPressure(cfg.Targets[0]) {
		t.Fatal("fixture did not record host pressure")
	}
	if err := db.SaveDiscoveredEndpoint(cfg.ScanID, map[string]string{"url": cfg.Targets[0], "method": "GET"}); err != nil {
		t.Fatal(err)
	}
	batcher := events.NewBatcher(noopWriter{}, 100, time.Hour)
	defer batcher.Close()
	e := &Engine{db: db, session: session.NewScanSession(cfg), client: client, scope: sc, verifier: verification.NewEngine(db, nil), batcher: batcher}
	defer e.vulnModuleRunner().Close()
	if err := e.runVulnModulesStage(ctx, "followup"); err != nil {
		t.Fatal(err)
	}
	if client.TotalRequests() <= 1 || e.moduleRunner.LastModuleStatus("http_methods") != "completed" {
		t.Fatalf("later module did not run: requests=%d status=%s", client.TotalRequests(), e.moduleRunner.LastModuleStatus("http_methods"))
	}
}
