package testlab_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/ratelimit"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/testlab"
)

func TestLabServerDirectAccess(t *testing.T) {
	lab := testlab.NewServer(testlab.ModeFull)
	defer lab.Close()

	resp, err := http.Get(lab.BaseURL())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestLabClientThroughScope(t *testing.T) {
	lab := testlab.NewServer(testlab.ModeFull)
	defer lab.Close()

	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{lab.ScopeDomain()}
	scopeEngine := scope.NewEngine(cfg)
	client, err := httpclient.New(cfg, scopeEngine, ratelimit.New(1000, 1000))
	if err != nil {
		t.Fatal(err)
	}
	rr, err := client.Do(context.Background(), "GET", lab.BaseURL(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rr.Response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", rr.Response.StatusCode)
	}
}
