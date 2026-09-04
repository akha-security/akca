package modules

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/reflection"
)

type recordedProbe struct {
	method  string
	rawURL  string
	body    []byte
	headers map[string]string
}

type recordingProbeClient struct {
	calls []recordedProbe
}

func (c *recordingProbeClient) Do(_ context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	call := recordedProbe{
		method:  method,
		rawURL:  rawURL,
		body:    append([]byte(nil), body...),
		headers: make(map[string]string, len(headers)),
	}
	for name, value := range headers {
		call.headers[name] = value
	}
	c.calls = append(c.calls, call)
	return httpclient.RequestResponse{
		Request: httpclient.RequestRecord{
			Method:  method,
			URL:     rawURL,
			Body:    string(body),
			Headers: call.headers,
		},
		Response: httpclient.ResponseRecord{StatusCode: http.StatusOK, Body: "ok"},
	}, nil
}

func TestInjectionProbeKeepsHeaderOnOriginalMethod(t *testing.T) {
	client := &recordingProbeClient{}
	runner := testRunner(t, client)
	payload := `'; SELECT pg_sleep(4)-- -`
	target := ScanTarget{
		EndpointURL: "http://example.com/actuator/health",
		Method:      http.MethodGet,
		Parameter:   "X-Original-URL",
		Location:    "header",
	}

	attempts := runner.injectionProbeAttempts(context.Background(), target, payload)
	if len(attempts) != 1 || len(client.calls) != 1 {
		t.Fatalf("expected exactly one native probe, got attempts=%d calls=%d", len(attempts), len(client.calls))
	}
	call := client.calls[0]
	if call.method != http.MethodGet {
		t.Fatalf("header probe changed method: got %s want GET", call.method)
	}
	if len(call.body) != 0 {
		t.Fatalf("header probe must not create a form body: %q", string(call.body))
	}
	if got := call.headers["X-Original-URL"]; got != payload {
		t.Fatalf("payload was not placed in header: got %q", got)
	}
	if strings.Contains(call.rawURL, "X-Original-URL") {
		t.Fatalf("header parameter leaked into URL: %s", call.rawURL)
	}
	if attempts[0].Target.Location != "header" || attempts[0].Target.Parameter != "X-Original-URL" {
		t.Fatalf("finding target lost native surface: %+v", attempts[0].Target)
	}
}

func TestHeaderOnlyModuleProbePreservesMethodAndURL(t *testing.T) {
	client := &recordingProbeClient{}
	runner := testRunner(t, client)
	target := ScanTarget{EndpointURL: "http://example.com/account?view=full", Method: http.MethodGet}
	if _, err := runner.probeHeadersOnlyForModule(context.Background(), "host_poisoning", target,
		map[string]string{"X-Forwarded-Host": "canary.invalid"}); err != nil {
		t.Fatal(err)
	}
	if len(client.calls) != 1 {
		t.Fatalf("calls=%d, want 1", len(client.calls))
	}
	call := client.calls[0]
	if call.method != http.MethodGet || call.rawURL != target.EndpointURL || len(call.body) != 0 {
		t.Fatalf("header-only probe changed request shape: %+v", call)
	}
	if call.headers["X-Forwarded-Host"] != "canary.invalid" {
		t.Fatalf("host poisoning header missing: %+v", call.headers)
	}
}

func TestOriginScopedModulesUseOneOriginKey(t *testing.T) {
	runner := &Runner{moduleSeen: make(map[string]struct{})}
	first := ScanTarget{EndpointURL: "https://example.com/products?q=one", Method: "GET"}
	second := ScanTarget{EndpointURL: "https://example.com/account?id=2", Method: "GET"}
	if !runner.endpointModuleOnce("actuator", first) || runner.endpointModuleOnce("actuator", second) {
		t.Fatal("actuator must run once per origin")
	}
	if !runner.endpointModuleOnce("http_methods", first) || !runner.endpointModuleOnce("http_methods", second) {
		t.Fatal("route-scoped modules must remain independent per path")
	}
	origin, ok := originScanTarget(first)
	if !ok || origin.EndpointURL != "https://example.com" || origin.Method != "GET" || origin.Parameter != "" {
		t.Fatalf("origin target = %+v, ok=%v", origin, ok)
	}
}

func TestActuatorProbesFromOriginInsteadOfCurrentPath(t *testing.T) {
	client := &recordingProbeClient{}
	runner := testRunner(t, client)
	target := ScanTarget{EndpointURL: "http://example.com/products/list?q=gifts", Method: http.MethodGet, Parameter: "q"}
	_ = runner.runSpringActuator(context.Background(), target)
	want := "http://example.com/actuator/env"
	found := false
	for _, call := range client.calls {
		if call.rawURL == want {
			found = true
		}
		if strings.Contains(call.rawURL, "/products/list/actuator/") {
			t.Fatalf("actuator path was appended to current route: %s", call.rawURL)
		}
	}
	if !found {
		t.Fatalf("origin actuator probe %q was not sent: %+v", want, client.calls)
	}
}

func TestInjectionProbeUsesProfileHeaderLocationWithoutFanout(t *testing.T) {
	client := &recordingProbeClient{}
	runner := testRunner(t, client)
	target := ScanTarget{
		EndpointURL: "http://example.com/actuator/health",
		Method:      http.MethodGet,
		Parameter:   "X-Original-URL",
		Profile: reflection.ReflectionProfile{
			ParameterLocation: "header",
		},
	}

	attempts := runner.injectionProbeAttempts(context.Background(), target, "probe")
	if len(attempts) != 1 || len(client.calls) != 1 {
		t.Fatalf("expected one profile-bound header probe, got attempts=%d calls=%d", len(attempts), len(client.calls))
	}
	if client.calls[0].method != http.MethodGet || len(client.calls[0].body) != 0 || client.calls[0].headers["X-Original-URL"] != "probe" {
		t.Fatalf("profile header was delivered on the wrong surface: %+v", client.calls[0])
	}
	if attempts[0].Target.Location != "header" {
		t.Fatalf("attempt location = %q, want header", attempts[0].Target.Location)
	}
}

func TestSQLiFindingRejectsMethodNotAllowedTiming(t *testing.T) {
	p := payloadgen.Payload{
		Value:          `'; SELECT pg_sleep(4)-- -`,
		VulnClass:      "sqli",
		ExpectedSignal: "timing",
	}
	baseline := httpclient.ResponseRecord{StatusCode: http.StatusOK, Body: "healthy"}
	probe := httpclient.ResponseRecord{StatusCode: http.StatusMethodNotAllowed, Body: "Method Not Allowed"}

	if sqliFindingAllowed(p, "timing_differential", baseline, probe, "") {
		t.Fatal("405 Method Not Allowed must never be accepted as timing SQLi evidence")
	}
}
