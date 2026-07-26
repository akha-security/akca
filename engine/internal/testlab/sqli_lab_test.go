package testlab_test

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/modules"
	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/ratelimit"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/testlab"
	"github.com/akha-security/akca/engine/internal/verification"
)

func TestLabSQLiPersistedFinding(t *testing.T) {
	lab := testlab.NewServer(testlab.ModeFull)
	defer lab.Close()

	db, err := storage.Open(t.TempDir() + "/sqli-lab.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_ = db.Migrate()
	scanID := "scan-sqli-lab"
	_ = db.EnsureScan(scanID)

	backend, err := url.Parse(lab.Server.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := testlab.NewLabTransport(testlab.DefaultDomain, backend)
	cfg := config.DefaultScanConfig()
	cfg.TestRoundTripper = transport
	cfg.Targets = []string{lab.BaseURL()}
	cfg.IncludeDomains = []string{lab.ScopeDomain(), testlab.DefaultDomain}

	scopeEngine := scope.NewEngine(cfg)
	client, err := httpclient.New(cfg, scopeEngine, ratelimit.New(1000, 1000))
	if err != nil {
		t.Fatal(err)
	}

	target := modules.ScanTarget{
		EndpointURL: strings.TrimRight(lab.Server.URL, "/") + "/api/users",
		Method:      "GET",
		Parameter:   "id",
		Location:    "query",
		Payloads: payloadgen.GenerationResult{Payloads: []payloadgen.Payload{
			{VulnClass: "sqli", Value: `' OR '1'='1`, Variant: "error", ExpectedSignal: "sql_error", Priority: 10, BudgetCost: 1},
			{VulnClass: "sqli", Value: `'`, Variant: "error_single_quote", ExpectedSignal: "sql_error", Priority: 10, BudgetCost: 1},
		}},
	}
	if !scopeEngine.IsInScope(target.EndpointURL) {
		t.Fatalf("target out of scope: %s (%s)", target.EndpointURL, scopeEngine.Explain(target.EndpointURL))
	}

	runner := modules.NewRunner(scanID, client, scopeEngine, db, verification.NewEngine(db, nil), nil, func(string, string, map[string]interface{}) error { return nil }, cfg)
	findings, err := runner.RunIntegrationSubset(context.Background(), []modules.ScanTarget{target})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected in-memory sqli finding")
	}
	stored, err := db.ListFindings(scanID, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) == 0 {
		t.Fatalf("expected persisted sqli finding, in-memory confidence=%s", findings[0].Confidence)
	}
}
