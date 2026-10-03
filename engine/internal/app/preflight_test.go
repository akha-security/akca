package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/oast"
	"github.com/akha-security/akca/engine/internal/storage"
)

func TestPreflightFailsFastOnBadGateway(t *testing.T) {
	if err := preflightStatusError(http.StatusBadGateway, false); err == nil {
		t.Fatal("HTTP 502 must stop the scan")
	}
}

func TestPreflightOnlyTreatsAuthStatusAsFatalWhenAuthConfigured(t *testing.T) {
	if err := preflightStatusError(http.StatusUnauthorized, false); err != nil {
		t.Fatalf("public 401 target should remain scannable: %v", err)
	}
	if err := preflightStatusError(http.StatusUnauthorized, true); err == nil {
		t.Fatal("configured authentication must be validated")
	}
}

func TestFailedOASTHealthCheckDisablesBlindCoverage(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	storage.SetDataDirOverride(t.TempDir())
	engine, err := New(noopWriter{})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	listener, err := oast.NewListener(engine.db, engine.Emit, oast.Config{PollInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	listener.SetScanID("scan-oast-health-failure")
	engine.oast = listener

	cfg := config.DefaultScanConfig()
	cfg.ScanID = "scan-oast-health-failure"
	cfg.Targets = []string{target.URL}
	cfg.EnableOAST = true
	engine.session.Config = cfg
	if err := engine.runPreflightValidation(context.Background(), cfg); err != nil {
		t.Fatalf("target preflight should continue without unhealthy OAST: %v", err)
	}
	if engine.OAST() != nil {
		t.Fatal("failed OAST health check left the listener active")
	}
	if engine.session.Config.EnableOAST {
		t.Fatal("failed OAST health check left blind module coverage enabled")
	}
}
