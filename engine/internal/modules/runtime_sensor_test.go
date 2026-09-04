package modules

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/sensor"
	"github.com/akha-security/akca/engine/internal/verification"
)

type runtimeSQLClient struct {
	collector     *sensor.Collector
	parameterized bool
	errorBody     bool
}

func (c *runtimeSQLClient) Do(_ context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	payload := ""
	if parsed, err := url.Parse(rawURL); err == nil {
		payload = parsed.Query().Get("tracking_nonce")
	}
	responseBody := "stable empty application response"
	if payload == "akca-sqli" {
		if c.errorBody {
			responseBody = "SQLSTATE[42000]: syntax error near quote"
		}
		_, _ = c.collector.Ingest(sensor.Event{
			TraceID:     "trace-" + requestHeader(headers, "X-Akca-Request-ID"),
			RequestID:   requestHeader(headers, "X-Akca-Request-ID"),
			ScanID:      requestHeader(headers, "X-Akca-Scan-ID"),
			CandidateID: requestHeader(headers, "X-Akca-Candidate-ID"),
			Endpoint:    requestHeader(headers, "X-Akca-Endpoint"),
			Parameter:   requestHeader(headers, "X-Akca-Parameter"),
			Platform:    "node",
			Source:      sensor.Source{Kind: "query", Name: "tracking_nonce", Location: "query", Tainted: true},
			Sinks: []sensor.Sink{{
				Type: "sql", Operation: "query", Tainted: true, Parameterized: c.parameterized,
			}},
			ObservedAt: time.Now().UTC(),
		})
	}
	return httpclient.RequestResponse{
		Request: httpclient.RequestRecord{Method: method, URL: rawURL, Body: string(body), Headers: headers},
		Response: httpclient.ResponseRecord{
			StatusCode: 200, Body: responseBody, Headers: map[string]string{"Content-Type": "text/plain"},
		},
	}, nil
}

func runtimeSQLRunner(client *runtimeSQLClient) *Runner {
	cfg := config.DefaultScanConfig()
	cfg.Targets = []string{"https://example.test"}
	client.collector.ActivateEndpoint("https://example.test/search")
	return NewRunner(
		"scan-runtime", client, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil), nil, nil, cfg,
		WithRuntimeSensor(client.collector),
	)
}

func runtimeSQLTarget() ScanTarget {
	return ScanTarget{
		EndpointURL: "https://example.test/search", Method: "GET",
		Parameter: "tracking_nonce", Location: "query",
		Payloads: payloadgen.GenerationResult{Payloads: []payloadgen.Payload{{
			VulnClass: "sqli", Value: "akca-sqli", ExpectedSignal: "sql_error", Variant: "runtime_test",
		}}},
	}
}

func TestRuntimeRawSQLConfirmsWithoutResponseSignal(t *testing.T) {
	collector := sensor.NewCollector("0123456789abcdef", nil)
	client := &runtimeSQLClient{collector: collector}
	findings := runtimeSQLRunner(client).runSQLi(context.Background(), runtimeSQLTarget())
	if len(findings) != 1 || findings[0].Evidence.Verification.ProofType != verification.ProofRuntimeTrace ||
		!findings[0].Evidence.Verification.ProofSatisfied {
		t.Fatalf("unsafe correlated SQL trace did not produce deterministic proof: %+v", findings)
	}
}

func TestRuntimePreparedSQLSuppressesResponseHeuristic(t *testing.T) {
	collector := sensor.NewCollector("0123456789abcdef", nil)
	client := &runtimeSQLClient{collector: collector, parameterized: true, errorBody: true}
	if findings := runtimeSQLRunner(client).runSQLi(context.Background(), runtimeSQLTarget()); len(findings) != 0 {
		t.Fatalf("prepared SQL safe evidence must suppress response-only SQLi heuristic: %+v", findings)
	}
}

func TestRuntimeCommandSinkConfirmsWithoutResponseSignal(t *testing.T) {
	collector := sensor.NewCollector("0123456789abcdef", nil)
	cfg := config.DefaultScanConfig()
	target := ScanTarget{
		EndpointURL: "https://example.test/run", Method: "GET",
		Parameter: "command", Location: "query",
	}
	collector.ActivateEndpoint(target.EndpointURL)
	runner := NewRunner(
		"scan-runtime-command", &runtimeSQLClient{collector: collector},
		scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil), nil, nil, cfg,
		WithRuntimeSensor(collector),
	)
	headers := runner.registerRuntimeProbe(target, "akca-command", nil)
	requestID := requestHeader(headers, "X-Akca-Request-ID")
	_, err := collector.Ingest(sensor.Event{
		TraceID: "trace-command", RequestID: requestID,
		ScanID:      requestHeader(headers, "X-Akca-Scan-ID"),
		CandidateID: requestHeader(headers, "X-Akca-Candidate-ID"),
		Endpoint:    target.EndpointURL, Parameter: target.Parameter, Platform: "node",
		Source: sensor.Source{Kind: "query", Name: target.Parameter, Location: "query", Tainted: true},
		Sinks: []sensor.Sink{{
			Type: "command", Operation: "exec", Tainted: true,
		}},
		ObservedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	baseline := httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: "GET", URL: target.EndpointURL},
		Response: httpclient.ResponseRecord{StatusCode: 200, Body: "stable"},
	}
	probe := httpclient.RequestResponse{
		Request: httpclient.RequestRecord{
			Method: "GET", URL: target.EndpointURL + "?command=akca-command", Headers: headers,
		},
		Response: httpclient.ResponseRecord{StatusCode: 200, Body: "stable"},
	}
	payload := payloadgen.Payload{VulnClass: "command_injection", Value: "akca-command", Variant: "runtime"}
	finding, handled := runner.runtimeSinkProof(
		context.Background(), "command_injection", target, payload, baseline, probe,
	)
	if !handled || finding == nil || finding.Evidence.Verification.ProofType != verification.ProofRuntimeTrace ||
		!finding.Evidence.Verification.ProofSatisfied {
		t.Fatalf("unsafe command sink did not produce runtime proof: handled=%v finding=%+v", handled, finding)
	}
}

func TestRuntimeSinkClassMapping(t *testing.T) {
	for _, test := range []struct {
		module string
		sink   string
	}{
		{"command_injection", "command"},
		{"ssti", "template"},
		{"ssrf", "http"},
		{"xxe", "xml"},
		{"lfi", "file"},
		{"ldap_xpath_injection", "ldap"},
		{"ldap_xpath_injection", "xpath"},
		{"deserialization", "deserialization"},
		{"react_rsc_rce", "deserialization"},
	} {
		if !runtimeSinkMatchesModule(test.module, test.sink) {
			t.Fatalf("runtime sink %s was not mapped to %s", test.sink, test.module)
		}
	}
	if runtimeSinkMatchesModule("ssrf", "file") {
		t.Fatal("unrelated runtime sink must not confirm a vulnerability class")
	}
}
