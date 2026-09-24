package modules

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/verification"
)

func TestNormalSQLReachesLaterClassicPayloads(t *testing.T) {
	for _, intensity := range []string{"normal", "fast"} {
		seen := map[string]int{}
		base := &budgetSurfaceClient{calls: map[string]int{}}
		client := auditDoer(func(ctx context.Context, m, u string, b []byte, h map[string]string) (httpclient.RequestResponse, error) {
			parsed, _ := url.Parse(u)
			seen[parsed.Query().Get("q")]++
			return base.Do(ctx, m, u, b, h)
		})
		cfg := config.DefaultScanConfig()
		cfg.ScanIntensity = intensity
		cfg.AllowedVulnerabilityClasses = []string{"sqli"}
		r := NewRunner("dialects", client, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil), nil, func(string, string, map[string]interface{}) error { return nil }, cfg)
		target := budgetTargets()[0]
		for i := 0; i < 12; i++ {
			target.Payloads.Payloads = append(target.Payloads.Payloads, payloadgen.Payload{VulnClass: "sqli", Variant: fmt.Sprintf("dialect_%d", i), Value: fmt.Sprintf("akca-dialect-%d", i), ExpectedSignal: "sql_error"})
		}
		if _, err := r.RunModule(context.Background(), "sqli", []ScanTarget{target}); err != nil {
			t.Fatal(err)
		}
		if intensity == "normal" && seen["akca-dialect-11"] == 0 {
			t.Fatal("normal scan skipped later classic dialects")
		}
		if intensity == "fast" && seen["akca-dialect-11"] != 0 {
			t.Fatal("explicit fast profile lost its scout optimization")
		}
	}
}

func TestRealHTTPAllocationIsChargedOnce(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.Write([]byte("stable safe page")) }))
	defer srv.Close()
	cfg := config.DefaultScanConfig()
	cfg.RequestBudget = 12
	cfg.AllowedVulnerabilityClasses = []string{"xss"}
	cfg.Targets = []string{srv.URL}
	cfg.PerHostRateLimit = 1000
	cfg.GlobalRateLimit = 1000
	sc := scope.NewEngine(cfg)
	client, err := httpclient.New(cfg, sc, nil)
	if err != nil {
		t.Fatal(err)
	}
	var finished map[string]interface{}
	r := NewRunner("wire", client, sc, nil, verification.NewEngine(nil, nil), nil, func(kind, _ string, data map[string]interface{}) error {
		if kind == "vuln_module_finished" {
			finished = data
		}
		return nil
	}, cfg)
	if _, err := r.RunModule(context.Background(), "xss", []ScanTarget{{EndpointURL: srv.URL + "?q=x", Method: "GET", Parameter: "q", Location: "query"}}); err == nil {
		t.Fatal("budget-limited module must report incomplete coverage")
	}
	if hits.Load() != 12 || finished["requests_used"] != int64(12) || finished["targets_budget_exhausted"] != 1 {
		t.Fatalf("double-charge or lost coverage: hits=%d event=%v", hits.Load(), finished)
	}
}

func TestBudgetCancellationAndUnusedModuleRollover(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.RequestBudget = 100
	cfg.AllowedVulnerabilityClasses = []string{"xss", "sqli"}
	r := NewRunner("rollover", nil, nil, nil, nil, nil, nil, cfg)
	first := r.allocateModuleBudget("xss", budgetTargets())
	r.finishModuleBudget("xss", first)
	second := r.allocateModuleBudget("sqli", budgetTargets())
	if second.allocated != 100 {
		t.Fatalf("unused module budget lost: %d", second.allocated)
	}
	client := &budgetSurfaceClient{calls: map[string]int{}}
	r = NewRunner("cancel", client, scope.NewEngine(cfg), nil, nil, nil, func(string, string, map[string]interface{}) error { return nil }, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.RunModule(ctx, "xss", budgetTargets()); err != context.Canceled {
		t.Fatalf("lost cancellation: %v", err)
	}
	if len(client.calls) != 0 {
		t.Fatal("canceled scan sent requests")
	}
}

type budgetSurfaceClient struct {
	mu    sync.Mutex
	calls map[string]int
}

func (c *budgetSurfaceClient) Do(ctx context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	u, _ := url.Parse(rawURL)
	c.mu.Lock()
	c.calls[u.Path]++
	c.mu.Unlock()
	if u.Path == "/vulnerable" {
		return (reflectedXSSSurfaceClient{}).Do(ctx, method, rawURL, body, headers)
	}
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: method, URL: rawURL},
		Response: httpclient.ResponseRecord{StatusCode: 200, Body: "<html><body>stable safe page</body></html>", Headers: map[string]string{"Content-Type": "text/html"}},
	}, nil
}

func budgetTargets() []ScanTarget {
	return []ScanTarget{
		{EndpointURL: "http://example.com/a-safe?q=hello", Method: "GET", Parameter: "q", Location: "query"},
		{EndpointURL: "http://example.com/b-safe?q=hello", Method: "GET", Parameter: "q", Location: "query"},
		{EndpointURL: "http://example.com/vulnerable?q=hello", Method: "GET", Parameter: "q", Location: "query"},
	}
}

func TestUnlimitedProductionLoaderReachesVulnerableEndpoint(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/budget.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureScan("budget-test"); err != nil {
		t.Fatal(err)
	}
	for _, target := range budgetTargets() {
		if err := db.SaveDiscoveredEndpoint("budget-test", map[string]interface{}{"url": target.EndpointURL, "method": "GET", "source": "test", "confidence": 1.0}); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.DefaultScanConfig()
	cfg.RequestBudget = 0
	cfg.PerHostConcurrency = 1
	cfg.EnableOAST = false
	client := &budgetSurfaceClient{calls: map[string]int{}}
	r := NewRunner("budget-test", client, scope.NewEngine(cfg), db, verification.NewEngine(db, nil), nil, func(string, string, map[string]interface{}) error { return nil }, cfg)
	findings, err := r.RunModuleFromDB(context.Background(), "xss", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || client.calls["/vulnerable"] == 0 {
		t.Fatalf("missed vulnerable endpoint: findings=%d calls=%v", len(findings), client.calls)
	}
	if client.calls["/a-safe"] < len(defaultXSSProbes())+1 || client.calls["/b-safe"] < len(defaultXSSProbes())+1 {
		t.Fatalf("unlimited probes truncated: %v", client.calls)
	}
}

func TestBoundedScanReservesLaterURLsAndReportsPartialCoverage(t *testing.T) {
	for _, workers := range []int{1, 8} {
		cfg := config.DefaultScanConfig()
		cfg.RequestBudget = 120
		cfg.PerHostConcurrency = workers
		cfg.AllowedVulnerabilityClasses = []string{"xss"}
		client := &budgetSurfaceClient{calls: map[string]int{}}
		var finished map[string]interface{}
		r := NewRunner("bounded", client, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil), nil,
			func(kind, _ string, data map[string]interface{}) error {
				if kind == "vuln_module_finished" {
					finished = data
				}
				return nil
			}, cfg)
		findings, err := r.RunModule(context.Background(), "xss", budgetTargets())
		if err == nil {
			t.Fatal("partial coverage must propagate to scan status")
		}
		if len(findings) != 1 || client.calls["/vulnerable"] == 0 {
			t.Fatalf("workers=%d: starved later URL: %v findings=%d", workers, client.calls, len(findings))
		}
		total := 0
		for _, n := range client.calls {
			total += n
		}
		if total > cfg.RequestBudget {
			t.Fatalf("exceeded hard budget: %d", total)
		}
		if finished["targets_budget_exhausted"].(int) == 0 || finished["coverage_percentage"] == "100.0%" {
			t.Fatalf("partial scan reported complete: %v", finished)
		}
	}
}

func TestSingleTargetBudgetCutIsNotComplete(t *testing.T) {
	for _, module := range []string{"xss", "sqli"} {
		cfg := config.DefaultScanConfig()
		cfg.RequestBudget = 10
		cfg.AllowedVulnerabilityClasses = []string{module}
		client := &budgetSurfaceClient{calls: map[string]int{}}
		var finished map[string]interface{}
		r := NewRunner("partial", client, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil), nil,
			func(kind, _ string, data map[string]interface{}) error {
				if kind == "vuln_module_finished" {
					finished = data
				}
				return nil
			}, cfg)
		_, err := r.RunModule(context.Background(), module, budgetTargets()[:1])
		if err == nil {
			t.Fatal("single-target budget cut must report incomplete coverage")
		}
		if finished["targets_tested"] != 0 || finished["targets_budget_exhausted"] != 1 || client.calls["/a-safe"] != 10 {
			t.Fatalf("%s: calls=%v event=%v", module, client.calls, finished)
		}
	}
}

func TestURLDerivedBudgetAndParameterFairness(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.RequestBudget = 0
	cfg.RequestsPerTarget = 40
	cfg.AllowedVulnerabilityClasses = []string{"xss"}
	r := NewRunner("derived", nil, nil, nil, nil, nil, nil, cfg)
	a, b := budgetTargets()[0], budgetTargets()[1]
	a2 := a
	a2.Parameter = "other"
	a2.EndpointURL = "http://example.com/a-safe?q=other"
	parameterless := a
	parameterless.Parameter = ""
	allocation := r.allocateModuleBudget("xss", []ScanTarget{a, a2, b, parameterless})
	if allocation.allocated != 80 || allocation.remaining[0] != 20 || allocation.remaining[1] != 20 || allocation.remaining[2] != 40 || allocation.remaining[3] != 0 {
		t.Fatalf("URL allocation inflated by parameters: %+v", allocation)
	}
	for i := 0; i < 20; i++ {
		if err := allocation.reserve(0); err != nil {
			t.Fatal(err)
		}
	}
	if err := allocation.reserve(0); err == nil {
		t.Fatal("stole another parameter's reservation")
	}
	allocation.release(1)
	if err := allocation.reserve(0); err != nil {
		t.Fatal("unused reservation not recycled", err)
	}
}

func TestModuleReservationsProtectSQLAfterXSS(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.RequestBudget = 300
	cfg.AllowedVulnerabilityClasses = []string{"xss", "sqli"}
	r := NewRunner("modules", nil, nil, nil, nil, nil, nil, cfg)
	first := r.allocateModuleBudget("xss", budgetTargets())
	if first.allocated == 0 || first.allocated >= 300 {
		t.Fatalf("no fair module split: %d", first.allocated)
	}
	for i := range first.remaining {
		for first.reserve(i) == nil {
		}
	}
	r.finishModuleBudget("xss", first)
	second := r.allocateModuleBudget("sqli", budgetTargets())
	if second.allocated == 0 || first.used+second.allocated != 300 {
		t.Fatalf("SQL reservation lost: xss=%d sql=%d", first.used, second.allocated)
	}
}

func TestExhaustedExplicitBudgetIsNotUnlimited(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.RequestBudget = 100
	cfg.AllowedVulnerabilityClasses = []string{"xss"}
	client := &budgetSurfaceClient{calls: map[string]int{}}
	r := NewRunner("zero", client, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil), nil, func(string, string, map[string]interface{}) error { return nil }, cfg, WithRemainingRequestBudget(0))
	if _, err := r.RunModule(context.Background(), "xss", budgetTargets()); err == nil {
		t.Fatal("exhausted budget must report incomplete coverage")
	}
	if len(client.calls) != 0 {
		t.Fatalf("exhausted explicit budget sent requests: %v", client.calls)
	}
}
