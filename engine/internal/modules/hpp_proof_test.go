package modules

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/verification"
)

type hppProofClient struct{ role string }

func (c *hppProofClient) Do(ctx context.Context, method, rawURL string, body []byte,
	headers map[string]string) (httpclient.RequestResponse, error) {
	return c.response(method, rawURL, body, headers), nil
}

func (c *hppProofClient) DoWithAuthProfile(ctx context.Context, method, rawURL string, body []byte,
	headers map[string]string, profile config.AuthProfile) (httpclient.RequestResponse, error) {
	return c.response(method, rawURL, body, headers), nil
}

func (c *hppProofClient) response(method, rawURL string, body []byte, headers map[string]string) httpclient.RequestResponse {
	status, responseBody := http.StatusOK, `{}`
	switch {
	case strings.HasSuffix(rawURL, "/state"):
		responseBody = `{"role":"` + c.role + `"}`
	case strings.HasSuffix(rawURL, "/cleanup"):
		c.role = "user"
	case strings.Contains(rawURL, "/change"):
		parsed, _ := url.Parse(rawURL)
		values := parsed.Query()["role"]
		if len(values) > 1 && values[0] == "admin" {
			c.role = "admin"
		}
	default:
		status = http.StatusNotFound
	}
	return httpclient.RequestResponse{
		Request: httpclient.RequestRecord{Method: method, URL: rawURL, Body: string(body), Headers: headers},
		Response: httpclient.ResponseRecord{StatusCode: status, Body: responseBody,
			Headers: map[string]string{"Content-Type": "application/json"}},
	}
}

func TestHPPRequiresRepeatedStateMutationAndCleanup(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.AuthProfiles = []config.AuthProfile{{ID: "user"}}
	cfg.HPPProofPolicies = []config.HPPProofPolicy{{
		ID: "role-precedence", URLContains: "/change", AuthProfileID: "user",
		ExpectedInvariant: "a user cannot become admin through duplicate role parameters",
		NativeValue:       "user", DuplicateValues: []string{"admin", "user"},
		State:                config.RecordedRequest{Method: "GET", URL: "http://example.com/state"},
		Cleanup:              config.RecordedRequest{Method: "POST", URL: "http://example.com/cleanup"},
		StateValueExpression: "json:role", ForbiddenValue: "admin",
	}}
	client := &hppProofClient{role: "user"}
	runner := NewRunner("scan-hpp", client, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil),
		nil, func(string, string, map[string]interface{}) error { return nil }, cfg)
	findings := runner.runHPP(context.Background(), ScanTarget{
		EndpointURL: "http://example.com/change", Method: "POST", Parameter: "role",
	})
	if len(findings) != 1 {
		t.Fatalf("expected state-proven HPP finding, got %d", len(findings))
	}
	if client.role != "user" {
		t.Fatal("HPP cleanup did not restore the original role")
	}
}
