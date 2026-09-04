package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
)

func TestSessionLifecycleNeverUsesAmbientSessionWithoutDisposablePolicy(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	cfg := config.DefaultScanConfig()
	cfg.CustomHeaders = map[string]string{"Authorization": "Bearer important-live-session"}
	runner, cleanup := newStatefulSecurityTestRunner(t, server.URL, cfg)
	defer cleanup()

	if findings := runner.runSessionLifecycle(context.Background(), ScanTarget{
		EndpointURL: server.URL + "/api/auth/logout", Method: http.MethodPost,
	}); len(findings) != 0 || requests.Load() != 0 {
		t.Fatalf("ambient session must not be logged out: findings=%d requests=%d", len(findings), requests.Load())
	}
}

func TestSessionLifecycleDisposableTokenReuseIsConfirmed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer disposable" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if request.URL.Path == "/api/auth/logout" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"user_id":123,"email":"scanner@example.test","private":true}`))
	}))
	defer server.Close()

	cfg := config.DefaultScanConfig()
	cfg.AuthProfiles = []config.AuthProfile{{ID: "disposable", Headers: map[string]string{"Authorization": "Bearer disposable"}}}
	cfg.SessionLifecycleProofPolicies = []config.SessionLifecycleProofPolicy{{
		ID: "logout-revocation", URLContains: "/api/auth/logout", AuthProfileID: "disposable",
		ExpectedInvariant: "Logout must revoke the dedicated test session", DisposableCredential: true,
		Logout:            config.RecordedRequest{Method: http.MethodPost, URL: server.URL + "/api/auth/logout", ExpectedStatuses: []int{http.StatusNoContent}},
		ProtectedResource: config.RecordedRequest{Method: http.MethodGet, URL: server.URL + "/api/user/profile"},
	}}
	runner, cleanup := newStatefulSecurityTestRunner(t, server.URL, cfg)
	defer cleanup()
	findings := runner.runSessionLifecycle(context.Background(), ScanTarget{
		EndpointURL: server.URL + "/api/auth/logout", Method: http.MethodPost,
	})
	if len(findings) != 1 || findings[0].Evidence.Verification.ProofType != "request_policy" {
		t.Fatalf("expected one request-policy session finding, got %#v", findings)
	}
}
