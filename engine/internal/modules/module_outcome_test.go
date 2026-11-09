package modules

import (
	"context"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/verification"
)

func TestRunModuleReportsSkippedWhenEveryTargetIsStatic(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.Targets = []string{"https://example.test/"}
	r := NewRunner("sqli-static-skip", auditDoer(func(context.Context, string, string, []byte, map[string]string) (httpclient.RequestResponse, error) {
		t.Fatal("SQLi should not send probes to a static JavaScript asset")
		return httpclient.RequestResponse{}, nil
	}), nil, nil, verification.NewEngine(nil, nil), nil, func(string, string, map[string]interface{}) error { return nil }, cfg)
	defer r.Close()

	_, err := r.RunModule(context.Background(), "sqli", []ScanTarget{{EndpointURL: "https://example.test/app.js", Method: "GET"}})
	if err != nil {
		t.Fatalf("skipped static-only module should not fail the scan: %v", err)
	}
	if got := r.LastModuleStatus("sqli"); got != "skipped" {
		t.Fatalf("module status = %q, want skipped", got)
	}
}
