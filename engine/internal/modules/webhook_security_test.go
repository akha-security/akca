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
)

func TestWebhookSecurityRequiresRecordedCleanupPolicy(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	runner, cleanup := newStatefulSecurityTestRunner(t, server.URL, config.DefaultScanConfig())
	defer cleanup()

	findings := runner.runWebhookSecurity(context.Background(), ScanTarget{
		EndpointURL: server.URL + "/api/stripe/webhook", Method: http.MethodPost,
	})
	if len(findings) != 0 || requests.Load() != 0 {
		t.Fatalf("webhook probing must fail closed without policy: findings=%d requests=%d", len(findings), requests.Load())
	}
}

func TestWebhookSecurityRequiresObservedStateChangeAndRestoresIt(t *testing.T) {
	var mu sync.Mutex
	processed := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch request.URL.Path {
		case "/state":
			_, _ = fmt.Fprintf(w, `{"processed":%d}`, processed)
		case "/negative":
			w.WriteHeader(http.StatusUnauthorized)
		case "/api/stripe/webhook":
			processed++
			w.WriteHeader(http.StatusAccepted)
		case "/cleanup":
			processed = 0
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := config.DefaultScanConfig()
	cfg.WebhookProofPolicies = []config.StatefulSecurityProofPolicy{{
		ID: "unsigned-payment-event", URLContains: "/api/stripe/webhook",
		ExpectedInvariant: "Unsigned payment events must not be processed",
		Action:            config.RecordedRequest{Method: http.MethodPost, URL: server.URL + "/api/stripe/webhook", Body: `{"id":"{{akca_canary}}"}`, ExpectedStatuses: []int{http.StatusAccepted}},
		NegativeControl:   config.RecordedRequest{Method: http.MethodPost, URL: server.URL + "/negative", ExpectedStatuses: []int{http.StatusUnauthorized}},
		State:             config.RecordedRequest{Method: http.MethodGet, URL: server.URL + "/state"},
		Cleanup:           config.RecordedRequest{Method: http.MethodDelete, URL: server.URL + "/cleanup", ExpectedStatuses: []int{http.StatusNoContent}},
	}}
	runner, cleanup := newStatefulSecurityTestRunner(t, server.URL, cfg)
	defer cleanup()
	findings := runner.runWebhookSecurity(context.Background(), ScanTarget{
		EndpointURL: server.URL + "/api/stripe/webhook", Method: http.MethodPost,
	})
	if len(findings) != 1 || findings[0].VulnClass != "webhook_security" {
		t.Fatalf("expected one state-backed webhook finding, got %#v", findings)
	}
	mu.Lock()
	defer mu.Unlock()
	if processed != 0 {
		t.Fatalf("webhook proof did not restore state: processed=%d", processed)
	}
}
