package testlab_test

import (
	"context"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/modules"
	"github.com/akha-security/akca/engine/internal/ratelimit"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/testlab"
	"github.com/akha-security/akca/engine/internal/verification"
)

func TestGraphQLLabEndpoint(t *testing.T) {
	lab := testlab.NewServer(testlab.ModeFull)
	defer lab.Close()

	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{lab.ScopeDomain()}
	client, _ := httpclient.New(cfg, scope.NewEngine(cfg), ratelimit.New(1000, 1000))
	db, _ := storage.Open(t.TempDir() + "/gql.db")
	defer db.Close()
	_ = db.Migrate()

	emit := func(string, string, map[string]interface{}) error { return nil }
	runner := modules.NewRunner("scan-gql", client, scope.NewEngine(cfg), db, verification.NewEngine(db, emit), nil, emit, cfg)
	target := modules.ScanTarget{
		EndpointURL: lab.Server.URL + "/graphql",
		Method:      "POST",
		Parameter:   "body",
	}
	findings, err := runner.RunIntegrationSubset(context.Background(), []modules.ScanTarget{target})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatal("introspection-only GraphQL endpoint must remain inventory, not a vulnerability finding")
	}
}
