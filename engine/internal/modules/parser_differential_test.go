package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/reflection"
)

func TestParserDifferentialDoesNotMutateStateChangingEndpoint(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"effective_role":"admin"}`))
	}))
	defer server.Close()
	runner, cleanup := newStatefulSecurityTestRunner(t, server.URL, config.DefaultScanConfig())
	defer cleanup()

	findings := runner.runParserDifferential(context.Background(), ScanTarget{
		EndpointURL: server.URL + "/api/v1/update-profile", Method: http.MethodPost,
		BodyTemplate: `{"role":"user"}`,
		Profile:      reflection.ReflectionProfile{ContentType: "application/json"},
	})
	if len(findings) != 0 {
		t.Fatalf("expected no unproven parser finding, got %d", len(findings))
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("parser differential sent %d state-changing requests", got)
	}
}
