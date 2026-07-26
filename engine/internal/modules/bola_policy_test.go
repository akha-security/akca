package modules

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/verification"
)

type bolaPolicyClient struct {
	anonymousPublic bool
	calls           []string
}

func (c *bolaPolicyClient) Do(_ context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	return c.response(method, rawURL, body, headers, "ambient"), nil
}

func (c *bolaPolicyClient) DoWithAuthProfile(_ context.Context, method, rawURL string, body []byte,
	headers map[string]string, profile config.AuthProfile) (httpclient.RequestResponse, error) {
	return c.response(method, rawURL, body, headers, profile.ID), nil
}

func (c *bolaPolicyClient) DoWithoutSession(_ context.Context, method, rawURL string, body []byte,
	headers map[string]string) (httpclient.RequestResponse, error) {
	return c.response(method, rawURL, body, headers, "anonymous"), nil
}

func (c *bolaPolicyClient) response(method, rawURL string, body []byte, headers map[string]string,
	identity string) httpclient.RequestResponse {
	c.calls = append(c.calls, identity+" "+rawURL)
	status := http.StatusOK
	responseBody := `{"id":"acct-7","owner":"alice","secret":"proof"}`
	if identity == "anonymous" && !c.anonymousPublic {
		status, responseBody = http.StatusUnauthorized, `{"error":"unauthorized"}`
	}
	if !strings.HasSuffix(rawURL, "/accounts/acct-7") {
		status, responseBody = http.StatusNotFound, `{"error":"not found"}`
	}
	return httpclient.RequestResponse{
		Request: httpclient.RequestRecord{Method: method, URL: rawURL, Body: string(body), Headers: headers},
		Response: httpclient.ResponseRecord{
			StatusCode: status, Body: responseBody, Headers: map[string]string{"Content-Type": "application/json"},
		},
	}
}

func TestBOLARequiresOwnershipPolicyAndProducesIdentityProof(t *testing.T) {
	cfg := bolaTestConfig()
	client := &bolaPolicyClient{}
	runner := NewRunner("scan-bola", client, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil),
		nil, func(string, string, map[string]interface{}) error { return nil }, cfg)
	target := ScanTarget{
		EndpointURL: "http://example.com/accounts/{id}", Method: http.MethodGet,
		Parameter: "id", Location: "path",
	}
	findings := runner.runIDOR(context.Background(), target)
	if len(findings) != 1 {
		t.Fatalf("expected one policy-backed BOLA finding, got %d calls=%v", len(findings), client.calls)
	}
	if findings[0].Evidence.Verification.ProofType != verification.ProofIdentityBoundary ||
		!findings[0].Evidence.Verification.ProofSatisfied {
		t.Fatalf("identity-bound proof was not satisfied: %+v", findings[0].Evidence.Verification)
	}
}

func TestBOLASharedOrUndeclaredResourceDoesNotBecomeFinding(t *testing.T) {
	target := ScanTarget{
		EndpointURL: "http://example.com/accounts/{id}", Method: http.MethodGet,
		Parameter: "id", Location: "path",
	}
	cfg := bolaTestConfig()
	cfg.ObjectAuthorizationPolicies = nil
	client := &bolaPolicyClient{}
	runner := NewRunner("scan-no-policy", client, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil),
		nil, func(string, string, map[string]interface{}) error { return nil }, cfg)
	if findings := runner.runIDOR(context.Background(), target); len(findings) != 0 || len(client.calls) != 0 {
		t.Fatalf("undeclared ownership must remain a coverage gap: findings=%d calls=%v", len(findings), client.calls)
	}

	cfg = bolaTestConfig()
	publicClient := &bolaPolicyClient{anonymousPublic: true}
	runner = NewRunner("scan-public", publicClient, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil),
		nil, func(string, string, map[string]interface{}) error { return nil }, cfg)
	if findings := runner.runIDOR(context.Background(), target); len(findings) != 0 {
		t.Fatalf("public/shared resource must not become BOLA, got %d", len(findings))
	}
}

func bolaTestConfig() config.ScanConfig {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"example.com"}
	cfg.AuthProfiles = []config.AuthProfile{
		{ID: "alice-auth", Name: "Alice"},
		{ID: "bob-auth", Name: "Bob"},
	}
	cfg.RoleProfiles = []config.RoleProfile{
		{ID: "alice", Name: "Alice owner", AuthProfileID: "alice-auth"},
		{ID: "bob", Name: "Bob foreign", AuthProfileID: "bob-auth"},
	}
	cfg.ObjectAuthorizationPolicies = []config.ObjectAuthorizationPolicy{{
		ID: "account-owner-only", URLContains: "/accounts/", Method: http.MethodGet,
		Parameter: "id", Location: "path", OwnerRoleProfileID: "alice", ForeignRoleProfileID: "bob",
		ResourceValues: []string{"acct-7"}, ExpectedPolicy: "only the account owner may read this object",
		RequireAnonymousDeny: true,
	}}
	return cfg
}
