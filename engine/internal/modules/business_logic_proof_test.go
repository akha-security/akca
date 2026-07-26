package modules

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/verification"
)

type businessProofClient struct {
	mu        sync.Mutex
	lastTotal int
	nextID    int
}

func (c *businessProofClient) Do(ctx context.Context, method, rawURL string, body []byte,
	headers map[string]string) (httpclient.RequestResponse, error) {
	return c.response(method, rawURL, body, headers), nil
}

func (c *businessProofClient) DoWithAuthProfile(ctx context.Context, method, rawURL string, body []byte,
	headers map[string]string, profile config.AuthProfile) (httpclient.RequestResponse, error) {
	return c.response(method, rawURL, body, headers), nil
}

func (c *businessProofClient) response(method, rawURL string, body []byte,
	headers map[string]string) httpclient.RequestResponse {
	c.mu.Lock()
	defer c.mu.Unlock()
	status, responseBody := http.StatusOK, `{}`
	switch {
	case strings.HasSuffix(rawURL, "/state"):
		responseBody = fmt.Sprintf(`{"last_total":%d}`, c.lastTotal)
	case strings.HasSuffix(rawURL, "/order") && string(body) == `{"price":10}`:
		c.nextID++
		c.lastTotal = 10
		responseBody = fmt.Sprintf(`{"order":{"id":"order-%d"}}`, c.nextID)
	case strings.HasSuffix(rawURL, "/order") && string(body) == `{"price":-100}`:
		c.nextID++
		c.lastTotal = -100
		responseBody = fmt.Sprintf(`{"order":{"id":"order-%d"}}`, c.nextID)
	case strings.HasSuffix(rawURL, "/order"):
		status, responseBody = http.StatusBadRequest, `{"error":"invalid input"}`
	case strings.Contains(rawURL, "/cleanup/"):
		c.lastTotal = 0
	default:
		status = http.StatusNotFound
	}
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Body: string(body), Headers: headers},
		Response: httpclient.ResponseRecord{StatusCode: status, Body: responseBody, Headers: map[string]string{"Content-Type": "application/json"}},
	}
}

func TestBusinessLogicProofRequiresForbiddenStateAndCleanup(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.EnableBusinessLogicChecks = true
	cfg.AuthProfiles = []config.AuthProfile{{ID: "buyer"}}
	cfg.BusinessLogicProofPolicies = []config.BusinessLogicProofPolicy{{
		ID: "negative-price", URLContains: "/order", AuthProfileID: "buyer",
		ExpectedInvariant: "order total must not be negative",
		NativeAction: config.RecordedRequest{
			Method: "POST", URL: "http://example.com/order", Body: `{"price":10}`, ContentType: "application/json",
		},
		ManipulatedAction: config.RecordedRequest{
			Method: "POST", URL: "http://example.com/order", Body: `{"price":-100}`, ContentType: "application/json",
		},
		NegativeControl: config.RecordedRequest{
			Method: "POST", URL: "http://example.com/order", Body: `{"price":"invalid"}`, ContentType: "application/json",
			ExpectedStatuses: []int{400},
		},
		State: config.RecordedRequest{Method: "GET", URL: "http://example.com/state"},
		Cleanup: config.RecordedRequest{
			Method: "DELETE", URL: "http://example.com/cleanup/{{transaction_id}}",
		},
		TransactionIDExpression: "json:order.id", StateValueExpression: "json:last_total", ForbiddenValue: "-100",
	}}
	client := &businessProofClient{}
	runner := NewRunner("scan-business", client, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil),
		nil, func(string, string, map[string]interface{}) error { return nil }, cfg)
	findings := runner.runBusinessLogic(context.Background(), ScanTarget{
		EndpointURL: "http://example.com/order", Method: "POST", Parameter: "price",
	})
	if len(findings) != 1 {
		t.Fatalf("expected one state-proven business logic finding, got %d", len(findings))
	}
	if client.lastTotal != 0 {
		t.Fatalf("business logic cleanup did not restore state: %d", client.lastTotal)
	}
}
