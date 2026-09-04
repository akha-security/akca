package modules

import (
	"context"
	"net/http"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/verification"
)

func TestTenantIsolationRequiresDeclaredOwnership(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"example.com"}
	client := &bolaPolicyClient{}
	runner := NewRunner("tenant-no-policy", client, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil), nil, nil, cfg)
	findings := runner.runTenantIsolation(context.Background(), ScanTarget{
		EndpointURL: "http://example.com/accounts/{id}", Method: http.MethodGet, Parameter: "id", Location: "path",
	})
	if len(findings) != 0 || len(client.calls) != 0 {
		t.Fatalf("undeclared tenant ownership must not be probed: findings=%d calls=%v", len(findings), client.calls)
	}
}

func TestTenantIsolationUsesExactOwnerForeignAndAnonymousProof(t *testing.T) {
	cfg := bolaTestConfig()
	client := &bolaPolicyClient{}
	runner := NewRunner("tenant-policy", client, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil), nil, nil, cfg)
	findings := runner.runTenantIsolation(context.Background(), ScanTarget{
		EndpointURL: "http://example.com/accounts/{id}", Method: http.MethodGet, Parameter: "id", Location: "path",
	})
	if len(findings) != 1 {
		t.Fatalf("expected one policy-backed tenant finding, got %d calls=%v", len(findings), client.calls)
	}
	if findings[0].Evidence.Verification.ProofType != verification.ProofIdentityBoundary ||
		!findings[0].Evidence.Verification.ProofSatisfied {
		t.Fatalf("tenant finding lacks identity-bound proof: %+v", findings[0].Evidence.Verification)
	}
}
