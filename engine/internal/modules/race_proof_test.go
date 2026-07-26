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

type raceProofClient struct {
	mu             sync.Mutex
	count          int
	nextID         int
	concurrentMode bool
	idempotent     bool
}

func (c *raceProofClient) Do(ctx context.Context, method, rawURL string, body []byte,
	headers map[string]string) (httpclient.RequestResponse, error) {
	return c.response(method, rawURL, body, headers), nil
}

func (c *raceProofClient) DoWithAuthProfile(ctx context.Context, method, rawURL string, body []byte,
	headers map[string]string, profile config.AuthProfile) (httpclient.RequestResponse, error) {
	return c.response(method, rawURL, body, headers), nil
}

func (c *raceProofClient) response(method, rawURL string, body []byte,
	headers map[string]string) httpclient.RequestResponse {
	c.mu.Lock()
	defer c.mu.Unlock()
	status, responseBody := http.StatusOK, `{}`
	switch {
	case strings.HasSuffix(rawURL, "/state"):
		responseBody = fmt.Sprintf(`{"count":%d}`, c.count)
	case strings.HasSuffix(rawURL, "/claim"):
		if c.idempotent {
			if c.count == 0 {
				c.count = 1
			}
			responseBody = `{"transaction":{"id":"tx-stable"}}`
			break
		}
		if c.count == 0 || c.concurrentMode {
			c.nextID++
			c.count++
			responseBody = fmt.Sprintf(`{"transaction":{"id":"tx-%d"}}`, c.nextID)
		} else {
			responseBody = `{"result":"already processed"}`
		}
	case strings.Contains(rawURL, "/cleanup/"):
		if c.count > 0 {
			c.count--
		}
		if c.count == 0 {
			c.concurrentMode = true
		}
	default:
		status = http.StatusNotFound
	}
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Body: string(body), Headers: headers},
		Response: httpclient.ResponseRecord{StatusCode: status, Body: responseBody, Headers: map[string]string{"Content-Type": "application/json"}},
	}
}

func TestRaceIdempotentSuccessWithOneSideEffectIsNotFinding(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.EnableRaceConditionTesting = true
	cfg.AuthProfiles = []config.AuthProfile{{ID: "user"}}
	cfg.RaceProofPolicies = []config.RaceProofPolicy{{
		ID: "idempotent", URLContains: "/claim", AuthProfileID: "user",
		Action: config.RecordedRequest{Method: "POST", URL: "http://example.com/claim"},
		State:  config.RecordedRequest{Method: "GET", URL: "http://example.com/state"},
		Cleanup: config.RecordedRequest{
			Method: "DELETE", URL: "http://example.com/cleanup/{{transaction_id}}",
		},
		TransactionIDExpression: "json:transaction.id", SequentialRuns: 5, ConcurrentRuns: 5,
	}}
	client := &raceProofClient{idempotent: true}
	runner := NewRunner("scan-race-safe", client, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil),
		nil, func(string, string, map[string]interface{}) error { return nil }, cfg)
	findings := runner.runRaceCondition(context.Background(), ScanTarget{
		EndpointURL: "http://example.com/claim", Method: "POST", Parameter: "claim",
	})
	if len(findings) != 0 {
		t.Fatalf("idempotent repeated success must not become race finding: %d", len(findings))
	}
	if client.count != 0 {
		t.Fatalf("idempotent control cleanup did not restore state: %d", client.count)
	}
}

func TestRaceProofUsesTransactionIDsStateAndCleanup(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.EnableRaceConditionTesting = true
	cfg.AuthProfiles = []config.AuthProfile{{ID: "user"}}
	cfg.RaceProofPolicies = []config.RaceProofPolicy{{
		ID: "claim-once", URLContains: "/claim", AuthProfileID: "user",
		Action: config.RecordedRequest{Method: "POST", URL: "http://example.com/claim"},
		State:  config.RecordedRequest{Method: "GET", URL: "http://example.com/state"},
		Cleanup: config.RecordedRequest{
			Method: "DELETE", URL: "http://example.com/cleanup/{{transaction_id}}",
		},
		TransactionIDExpression: "json:transaction.id", SequentialRuns: 5, ConcurrentRuns: 5,
	}}
	client := &raceProofClient{}
	runner := NewRunner("scan-race", client, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil),
		nil, func(string, string, map[string]interface{}) error { return nil }, cfg)
	findings := runner.runRaceCondition(context.Background(), ScanTarget{
		EndpointURL: "http://example.com/claim", Method: "POST", Parameter: "claim",
	})
	if len(findings) != 1 {
		t.Fatalf("expected state-proven race finding, got %d", len(findings))
	}
	if client.count != 0 {
		t.Fatalf("race proof cleanup did not restore state: %d", client.count)
	}
	if findings[0].Evidence.Verification.ProofType != verification.ProofStateMutation {
		t.Fatalf("unexpected proof type: %s", findings[0].Evidence.Verification.ProofType)
	}
}
