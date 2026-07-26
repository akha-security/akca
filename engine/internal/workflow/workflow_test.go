package workflow

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/safemutation"
)

type workflowDoer struct {
	requests []httpclient.RequestRecord
	failURL  string
}

func (d *workflowDoer) Do(_ context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	request := httpclient.RequestRecord{Method: method, URL: rawURL, Body: string(body), Headers: headers}
	d.requests = append(d.requests, request)
	if d.failURL != "" && strings.Contains(rawURL, d.failURL) {
		return httpclient.RequestResponse{}, errors.New("forced step failure")
	}
	response := httpclient.ResponseRecord{StatusCode: 200, Body: `{"id":"order-7"}`}
	return httpclient.RequestResponse{Request: request, Response: response}, nil
}

func TestWorkflowFailureStillRunsCleanupAndSnapshotVerification(t *testing.T) {
	doer := &workflowDoer{failURL: "/fail"}
	executor := NewExecutor(doer, safemutation.DefaultPolicy())
	_, err := executor.Run(context.Background(), Definition{
		ID: "cleanup-on-error",
		Steps: []Step{
			{
				ID: "create", Method: "POST", URL: "https://app.test/orders",
				Risk:     safemutation.ReversibleWrite,
				Cleanup:  &Step{ID: "cleanup", Method: "DELETE", URL: "https://app.test/orders/order-7"},
				Snapshot: &Step{ID: "snapshot", Method: "GET", URL: "https://app.test/orders/state"},
			},
			{ID: "fail", Method: "GET", URL: "https://app.test/fail", Risk: safemutation.ReadOnly},
		},
	}, nil)
	if err == nil {
		t.Fatal("expected the forced workflow error")
	}
	var cleanupSeen, verificationSeen bool
	for _, request := range doer.requests {
		if request.Method == "DELETE" {
			cleanupSeen = true
		}
		if cleanupSeen && request.Method == "GET" && strings.HasSuffix(request.URL, "/state") {
			verificationSeen = true
		}
	}
	if !cleanupSeen || !verificationSeen {
		t.Fatalf("error path skipped cleanup verification: %+v", doer.requests)
	}
}

func TestWorkflowBindsDependenciesAndCleansUpInReverse(t *testing.T) {
	doer := &workflowDoer{}
	executor := NewExecutor(doer, safemutation.DefaultPolicy())
	result, err := executor.Run(context.Background(), Definition{
		ID: "checkout", Steps: []Step{
			{
				ID: "create", Method: "POST", URL: "https://app.test/orders", Body: `{"item":"1"}`,
				Risk: safemutation.ReversibleWrite, Extract: map[string]string{"order_id": "json:id"},
				Cleanup:  &Step{ID: "create:cleanup", Method: "DELETE", URL: "https://app.test/orders/{{order_id}}", ExpectStatus: []int{200}},
				Snapshot: &Step{ID: "create:snapshot", Method: "GET", URL: "https://app.test/orders/state", ExpectStatus: []int{200}},
			},
			{ID: "read", Method: "GET", URL: "https://app.test/orders/{{order_id}}", Risk: safemutation.ReadOnly},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Variables["order_id"] != "order-7" || len(doer.requests) != 5 {
		t.Fatalf("unexpected workflow result: %+v requests=%+v", result, doer.requests)
	}
	if doer.requests[0].Method != "GET" || !strings.HasSuffix(doer.requests[2].URL, "/order-7") ||
		doer.requests[3].Method != "DELETE" || doer.requests[4].Method != "GET" {
		t.Fatalf("dependency or cleanup order failed: %+v", doer.requests)
	}
	if !strings.HasPrefix(doer.requests[1].Headers["X-Akca-Canary"], "akca-") {
		t.Fatal("write did not carry its unique Akca canary")
	}
}

func TestRecorderRejectsSyntheticStep(t *testing.T) {
	recorder := NewRecorder("id", "name", "user")
	if err := recorder.Record("bad", httpclient.RequestResponse{}, safemutation.ReadOnly, nil); err == nil {
		t.Fatal("synthetic workflow step must be rejected")
	}
}

func TestRecorderRemovesCapturedAuthenticationSecrets(t *testing.T) {
	recorder := NewRecorder("wf-secret", "captured", "user")
	err := recorder.Record("step-1", httpclient.RequestResponse{
		Request: httpclient.RequestRecord{
			Method: "POST", URL: "https://example.com/login", Body: "username=alice&password=do-not-store",
			Headers: map[string]string{
				"Authorization": "Bearer secret", "Cookie": "session=secret", "Accept": "application/json",
				"Content-Type": "application/x-www-form-urlencoded",
			},
		},
		Response: httpclient.ResponseRecord{StatusCode: 200, Body: `{"id":1}`},
	}, safemutation.ReadOnly, nil)
	if err != nil {
		t.Fatal(err)
	}
	step := recorder.Definition().Steps[0]
	if step.Headers["Authorization"] != "" || step.Headers["Cookie"] != "" {
		t.Fatal("captured workflow must not persist authentication secrets")
	}
	if step.Headers["Accept"] != "application/json" {
		t.Fatal("non-sensitive request context should be retained")
	}
	if strings.Contains(step.Body, "do-not-store") || !strings.Contains(step.Body, "{{secret_password}}") {
		t.Fatalf("captured body secret was not replaced with an explicit binding: %q", step.Body)
	}
	executor := NewExecutor(&workflowDoer{}, safemutation.DefaultPolicy())
	if _, err := executor.Run(context.Background(), recorder.Definition(), nil); err == nil {
		t.Fatal("workflow replay must fail closed until captured secret bindings are supplied")
	}
	if _, err := executor.Run(context.Background(), recorder.Definition(), map[string]string{"secret_password": "runtime-only"}); err != nil {
		t.Fatalf("explicit runtime secret binding should allow replay: %v", err)
	}
}

func TestRecorderRedactsNestedJSONSecrets(t *testing.T) {
	recorder := NewRecorder("wf-json-secret", "captured", "user")
	err := recorder.Record("step-1", httpclient.RequestResponse{
		Request: httpclient.RequestRecord{
			Method: "POST", URL: "https://example.com/token",
			Body:    `{"user":"alice","auth":{"access_token":"token-value","password":"password-value"}}`,
			Headers: map[string]string{"Content-Type": "application/json"},
		},
		Response: httpclient.ResponseRecord{StatusCode: 200},
	}, safemutation.ReadOnly, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := recorder.Definition().Steps[0].Body
	if strings.Contains(body, "token-value") || strings.Contains(body, "password-value") ||
		!strings.Contains(body, "{{secret_access_token}}") || !strings.Contains(body, "{{secret_password}}") {
		t.Fatalf("nested JSON secrets were not redacted: %s", body)
	}
}
