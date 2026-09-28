package modules

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/verification"
)

type sqliLabClient struct {
	parameter string
	native    string
	baseline  string
	responses map[string]string
	statuses  map[string]int
}

func (c *sqliLabClient) Do(_ context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	value := ""
	if parsed, err := url.Parse(rawURL); err == nil {
		value = parsed.Query().Get(c.parameter)
	}
	if len(body) > 0 {
		if form, err := url.ParseQuery(string(body)); err == nil && form.Has(c.parameter) {
			value = form.Get(c.parameter)
		}
	}
	responseBody := c.baseline
	if mapped, ok := c.responses[value]; ok {
		responseBody = mapped
	}
	status := 200
	if configured := c.statuses[value]; configured != 0 {
		status = configured
	}
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Body: string(body), Headers: headers},
		Response: httpclient.ResponseRecord{StatusCode: status, Body: responseBody, Headers: map[string]string{"Content-Type": "text/html"}},
	}, nil
}

func newSQLiLabRunner(client HTTPDoer) *Runner {
	cfg := config.DefaultScanConfig()
	cfg.RequestBudget = 0
	return NewRunner("scan-sqli-lab", client, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil), nil,
		func(string, string, map[string]interface{}) error { return nil }, cfg)
}

func TestBurpBountySQLiRegressionSixSurfaces(t *testing.T) {
	t.Run("error search", func(t *testing.T) {
		errorBody := `<h1>Database Error</h1><p>Warning: mysql_fetch_array()</p><p>You have an error in your SQL syntax</p><p>ORA-00933</p><p>Microsoft OLE DB Provider for SQL Server</p><p>Unclosed quotation mark</p><p>pg_query(): unterminated quoted string</p>`
		client := &sqliLabClient{parameter: "q", native: "laptop", baseline: "normal product results", responses: map[string]string{}, statuses: map[string]int{}}
		for _, value := range []string{"laptop'", `laptop"`, `laptop'"`, `laptop')`, `'`, `"`, `')`, `' OR 1=1--`} {
			client.responses[value] = errorBody
			client.statuses[value] = 500
		}
		target := ScanTarget{EndpointURL: "http://lab.test/sqli/search?q=laptop", Method: "GET", Parameter: "q", Location: "query"}
		if findings := newSQLiLabRunner(client).runSQLi(context.Background(), target); len(findings) == 0 || findings[0].Evidence.Signal != "error_based" {
			t.Fatalf("error-based search SQLi was missed: %+v", findings)
		}
	})

	t.Run("padded LIKE length", func(t *testing.T) {
		target := ScanTarget{EndpointURL: "http://lab.test/sqli/length?q=admin", Method: "GET", Parameter: "q", Location: "query"}
		pair := findSQLiPair(t, target, "boolean_like_percent_balanced")
		padding := strings.Repeat("<!-- stable padding -->", 500)
		baseline := "<div class=user-card>admin</div>" + padding
		falseBody := "<div class=empty>No users</div>" + padding
		client := pairClient("q", "admin", baseline, falseBody, pair)
		if findings := newSQLiLabRunner(client).booleanBlindSQLiProbe(context.Background(), target, baselineRR(target, baseline)); len(findings) != 1 {
			t.Fatalf("padding-aware LIKE SQLi was missed: %+v", findings)
		}
	})

	for _, parameter := range []string{"username", "password"} {
		t.Run("login "+parameter, func(t *testing.T) {
			body := "username=WfxYANoW&password=u%5DH%5Bww6KrA9F.x-F"
			target := ScanTarget{EndpointURL: "http://lab.test/sqli/login", Method: "POST", Parameter: parameter, Location: "form", BodyTemplate: body}
			target.RequestTemplate.Method = "POST"
			target.RequestTemplate.URL = target.EndpointURL
			target.RequestTemplate.Body = body
			target.RequestTemplate.ContentType = "application/x-www-form-urlencoded"
			pair := findSQLiPair(t, target, "boolean_auth_arithmetic_or")
			native := nativeTargetValue(target)
			client := pairClient(parameter, native, "Invalid credentials", "Invalid credentials", pair)
			client.responses[pair.trueVal] = "Welcome admin!"
			client.responses[pair.secondTrueVal] = "Welcome admin!"
			if findings := newSQLiLabRunner(client).booleanBlindSQLiProbe(context.Background(), target, baselineRR(target, "Invalid credentials")); len(findings) != 1 {
				t.Fatalf("POST form SQLi for %s was missed: %+v", parameter, findings)
			}
		})
	}

	for _, route := range []string{"time", "user"} {
		t.Run("numeric "+route, func(t *testing.T) {
			target := ScanTarget{EndpointURL: "http://lab.test/sqli/" + route + "?id=1", Method: "GET", Parameter: "id", Location: "query"}
			client := &sqliLabClient{parameter: "id", native: "1", baseline: "User: admin", responses: map[string]string{
				"1/((6-4)*(2-1)-2)": "User not found", "(1-999999)": "User not found",
				"1-1": "User not found", "1*0": "User not found",
			}, statuses: map[string]int{}}
			findings := newSQLiLabRunner(client).numericArithmeticSQLiProbe(context.Background(), target, baselineRR(target, "User: admin"))
			if len(findings) != 1 || findings[0].Evidence.Signal != "numeric_arithmetic_oracle" {
				t.Fatalf("numeric expression oracle for %s was missed: %+v", route, findings)
			}
		})
	}
}

func findSQLiPair(t *testing.T, target ScanTarget, variant string) sqliBooleanPair {
	t.Helper()
	for _, pair := range sqliBooleanPairs("scan-sqli-lab", target) {
		if pair.variant == variant {
			return pair
		}
	}
	t.Fatalf("SQLi pair %s not found", variant)
	return sqliBooleanPair{}
}

func pairClient(parameter, native, baseline, falseBody string, pair sqliBooleanPair) *sqliLabClient {
	return &sqliLabClient{parameter: parameter, native: native, baseline: baseline, responses: map[string]string{
		pair.trueVal: baseline, pair.falseVal: falseBody,
		pair.secondTrueVal: baseline, pair.secondFalseVal: falseBody,
		native: baseline,
	}, statuses: map[string]int{}}
}

func baselineRR(target ScanTarget, body string) httpclient.RequestResponse {
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: target.Method, URL: target.EndpointURL, Body: target.BodyTemplate},
		Response: httpclient.ResponseRecord{StatusCode: 200, Body: body, Headers: map[string]string{"Content-Type": "text/html"}},
	}
}
