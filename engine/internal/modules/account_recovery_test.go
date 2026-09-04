package modules

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/ratelimit"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/verification"
)

func TestAccountRecoveryRequiresRecordedCleanupPolicy(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	runner, cleanup := newStatefulSecurityTestRunner(t, server.URL, config.DefaultScanConfig())
	defer cleanup()
	findings := runner.runAccountRecovery(context.Background(), ScanTarget{
		EndpointURL: server.URL + "/api/auth/reset-password", Method: http.MethodPost,
	})
	if len(findings) != 0 {
		t.Fatalf("expected no finding without a state/cleanup policy, got %d", len(findings))
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("unsafe recovery module sent %d requests without a policy", got)
	}
}

func TestAccountRecoveryRecordedStateMutationIsConfirmedAndRestored(t *testing.T) {
	var mu sync.Mutex
	state := "original"
	var actionCalls, cleanupCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch request.URL.Path {
		case "/state":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"account_state":%q}`, state)
		case "/negative":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"token required"}`))
		case "/api/auth/reset-password":
			actionCalls++
			state = "changed"
			_, _ = w.Write([]byte(`{"accepted":true}`))
		case "/cleanup":
			cleanupCalls++
			state = "original"
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := config.DefaultScanConfig()
	cfg.AccountRecoveryProofPolicies = []config.StatefulSecurityProofPolicy{{
		ID: "reset-without-token", URLContains: "/api/auth/reset-password",
		ExpectedInvariant: "A reset token must be required before account state changes",
		Action:            config.RecordedRequest{Method: http.MethodPost, URL: server.URL + "/api/auth/reset-password", Body: `{"password":"{{akca_canary}}"}`},
		NegativeControl:   config.RecordedRequest{Method: http.MethodPost, URL: server.URL + "/negative", ExpectedStatuses: []int{http.StatusBadRequest}},
		State:             config.RecordedRequest{Method: http.MethodGet, URL: server.URL + "/state"},
		Cleanup:           config.RecordedRequest{Method: http.MethodPost, URL: server.URL + "/cleanup", ExpectedStatuses: []int{http.StatusNoContent}},
	}}
	runner, cleanup := newStatefulSecurityTestRunner(t, server.URL, cfg)
	defer cleanup()
	findings := runner.runAccountRecovery(context.Background(), ScanTarget{
		EndpointURL: server.URL + "/api/auth/reset-password", Method: http.MethodPost,
	})
	if len(findings) != 1 || findings[0].VulnClass != "account_recovery" {
		t.Fatalf("expected one confirmed account recovery finding, got %#v", findings)
	}
	mu.Lock()
	defer mu.Unlock()
	if state != "original" || actionCalls != 1 || cleanupCalls != 1 {
		t.Fatalf("expected one action and verified cleanup, state=%q action=%d cleanup=%d", state, actionCalls, cleanupCalls)
	}
}

func newStatefulSecurityTestRunner(t *testing.T, target string, cfg config.ScanConfig) (*Runner, func()) {
	t.Helper()
	cfg.Targets = []string{target}
	cfg.IncludeDomains = []string{"127.0.0.1"}
	cfg.ScanID = "stateful-security-test"
	scopeEngine := scope.NewEngine(cfg)
	client, err := httpclient.New(cfg, scopeEngine, ratelimit.New(cfg.GlobalRateLimit, cfg.PerHostRateLimit))
	if err != nil {
		t.Fatalf("httpclient.New: %v", err)
	}
	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := db.EnsureScan(cfg.ScanID); err != nil {
		t.Fatalf("EnsureScan: %v", err)
	}
	verifier := verification.NewEngine(db, nil)
	return NewRunner(cfg.ScanID, client, scopeEngine, db, verifier, nil, nil, cfg), func() { _ = db.Close() }
}
