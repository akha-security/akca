package modules

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
)

func TestCSRFRequiresPersistedStateAndVerifiedCleanup(t *testing.T) {
	var mu sync.Mutex
	balance := 100
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if request.Header.Get("Authorization") != "Bearer csrf-test" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch request.URL.Path {
		case "/state":
			_, _ = fmt.Fprintf(w, `{"balance":%d}`, balance)
		case "/transfer-invalid-token":
			w.WriteHeader(http.StatusForbidden)
		case "/transfer":
			balance = 90
			w.WriteHeader(http.StatusNoContent)
		case "/cleanup":
			balance = 100
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := config.DefaultScanConfig()
	cfg.AuthProfiles = []config.AuthProfile{{ID: "csrf-user", Headers: map[string]string{"Authorization": "Bearer csrf-test"}}}
	cfg.CSRFProofPolicies = []config.StatefulSecurityProofPolicy{{
		ID: "transfer-csrf", URLContains: "/transfer", AuthProfileID: "csrf-user",
		ExpectedInvariant: "Cross-site requests without a valid anti-CSRF token must not transfer funds",
		Action: config.RecordedRequest{Method: http.MethodPost, URL: server.URL + "/transfer", Body: "amount=10", ExpectedStatuses: []int{http.StatusNoContent}, Headers: map[string]string{
			"Origin": "https://attacker.invalid", "Referer": "https://attacker.invalid/proof",
		}},
		NegativeControl: config.RecordedRequest{Method: http.MethodPost, URL: server.URL + "/transfer-invalid-token", Body: "amount=10&csrf=invalid", ExpectedStatuses: []int{http.StatusForbidden}},
		State:           config.RecordedRequest{Method: http.MethodGet, URL: server.URL + "/state"},
		Cleanup:         config.RecordedRequest{Method: http.MethodPost, URL: server.URL + "/cleanup", ExpectedStatuses: []int{http.StatusNoContent}},
	}}
	runner, cleanup := newStatefulSecurityTestRunner(t, server.URL, cfg)
	defer cleanup()
	findings := runner.runCSRF(context.Background(), ScanTarget{EndpointURL: server.URL + "/transfer", Method: http.MethodPost})
	if len(findings) != 1 || findings[0].VulnClass != "csrf" {
		t.Fatalf("expected one state-backed CSRF finding, got %#v", findings)
	}
	mu.Lock()
	defer mu.Unlock()
	if balance != 100 {
		t.Fatalf("CSRF proof did not restore state: balance=%d", balance)
	}
}
