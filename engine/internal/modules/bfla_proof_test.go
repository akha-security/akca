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

type bflaProofClient struct {
	enabled bool
	calls   []string
}

func (c *bflaProofClient) Do(ctx context.Context, method, rawURL string, body []byte,
	headers map[string]string) (httpclient.RequestResponse, error) {
	return c.response(method, rawURL, body, headers, "shared"), nil
}

func (c *bflaProofClient) DoWithAuthProfile(ctx context.Context, method, rawURL string, body []byte,
	headers map[string]string, profile config.AuthProfile) (httpclient.RequestResponse, error) {
	return c.response(method, rawURL, body, headers, profile.ID), nil
}

func (c *bflaProofClient) DoWithoutSession(ctx context.Context, method, rawURL string, body []byte,
	headers map[string]string) (httpclient.RequestResponse, error) {
	return c.response(method, rawURL, body, headers, "anonymous"), nil
}

func (c *bflaProofClient) response(method, rawURL string, body []byte, headers map[string]string,
	identity string) httpclient.RequestResponse {
	c.calls = append(c.calls, identity+" "+method+" "+rawURL)
	status := http.StatusOK
	responseBody := `{"enabled":false}`
	switch {
	case strings.HasSuffix(rawURL, "/state") && identity == "anonymous":
		status, responseBody = http.StatusUnauthorized, `{"error":"unauthorized"}`
	case strings.HasSuffix(rawURL, "/state"):
		if c.enabled {
			responseBody = `{"enabled":true}`
		}
	case strings.HasSuffix(rawURL, "/admin/enable"):
		c.enabled = true
		responseBody = `{"accepted":true}`
	case strings.HasSuffix(rawURL, "/admin/disable") && identity == "high":
		c.enabled = false
		responseBody = `{"accepted":true}`
	default:
		status, responseBody = http.StatusNotFound, `{"error":"not found"}`
	}
	return httpclient.RequestResponse{
		Request: httpclient.RequestRecord{
			Method: method, URL: rawURL, Body: string(body), Headers: headers,
		},
		Response: httpclient.ResponseRecord{
			StatusCode: status, Body: responseBody, Headers: map[string]string{"Content-Type": "application/json"},
		},
	}
}

func TestBFLARequiresRealRolesStateProofAndCleanup(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.AuthProfiles = []config.AuthProfile{{ID: "low"}, {ID: "high"}}
	cfg.RoleProfiles = []config.RoleProfile{
		{ID: "user", AuthProfileID: "low"},
		{ID: "admin", AuthProfileID: "high"},
	}
	cfg.AuthorizationPolicies = []config.AuthorizationPolicy{{
		ID: "enable-setting", URLContains: "/admin/enable", Method: http.MethodPost,
		LowRoleProfileID: "low", HighRoleProfileID: "high",
		ExpectedRolePolicy: "only administrators may enable this setting",
		StateURL:           "http://example.com/state", StateMethod: http.MethodGet,
		CleanupURL: "http://example.com/admin/disable", CleanupMethod: http.MethodPost,
		RequireAnonymousDeny: true,
	}}
	client := &bflaProofClient{}
	runner := NewRunner("scan-bfla", client, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil),
		nil, func(string, string, map[string]interface{}) error { return nil }, cfg)
	target := ScanTarget{EndpointURL: "http://example.com/admin/enable", Method: http.MethodPost, Parameter: "enabled"}

	findings := runner.runBFLA(context.Background(), target)
	if len(findings) != 1 {
		t.Fatalf("expected one state-proven BFLA finding, got %d; calls=%v", len(findings), client.calls)
	}
	if client.enabled {
		t.Fatal("BFLA proof must restore the original state")
	}
	if !findings[0].Evidence.Verification.ProofSatisfied {
		t.Fatal("expected centralized proof policy to be satisfied")
	}
}
