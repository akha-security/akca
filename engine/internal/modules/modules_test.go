package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/nosql"
	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/reflection"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/verification"
)

func TestAllCatalogModulesAreCoveredByRunner(t *testing.T) {
	covered := map[string]struct{}{}
	for _, name := range []string{
		"xss", "blind_xss", "sqli", "nosql", "ssti", "command_injection",
		"ssrf", "xxe", "lfi", "file_upload", "idor", "bfla", "open_redirect", "host_header", "second_order",
		"cors", "jwt", "oauth", "cache_poisoning", "cache_deception", "mass_assignment", "api_exposure",
		"rate_limit", "account_enum", "hpp", "broken_auth", "csrf", "wordpress_fuzz",
		"security_headers", "tls_misconfig", "vulnerable_components", "sensitive_data", "secret_exposure",
		"cicd_exposure", "git_recovery", "source_code_disclosure", "graphql", "script_source", "websocket",
		"cloud_storage", "cloud_posture", "client_ssti", "smuggling",
		"prototype_pollution", "ldap_xpath_injection", "debug_admin", "business_logic", "race_condition",
		"api_versioning", "known_cve",
	} {
		covered[name] = struct{}{}
	}

	var missing []string
	for _, module := range ModuleCatalog() {
		if _, ok := covered[module]; !ok {
			missing = append(missing, module)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("modules not covered by runner orchestration: %v", missing)
	}
}

func TestAllCatalogModulesHaveProofPolicy(t *testing.T) {
	var missing []string
	for _, module := range ModuleCatalog() {
		policy, ok := verification.ProofPolicy(module)
		if !ok || policy.Version != verification.CurrentProofPolicyVersion ||
			policy.EvidenceClass == "" || len(policy.AllowedProofTypes) == 0 {
			missing = append(missing, module)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("vulnerability parity is missing proof policies: %v", missing)
	}
}

type mockClient struct {
	responses map[string]string
	delays    map[string]time.Duration
}

func (m *mockClient) Do(_ context.Context, method, rawURL string, _ []byte, _ map[string]string) (httpclient.RequestResponse, error) {
	u, _ := url.Parse(rawURL)
	key := u.Query().Get("q")
	if key == "" {
		key = u.Query().Get("id")
	}
	body := m.responses[key]
	if body == "" {
		body = m.responses["__default__"]
	}
	delay := m.delays[key]
	if delay > 0 {
		time.Sleep(delay)
	}
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: method, URL: rawURL},
		Response: httpclient.ResponseRecord{StatusCode: 200, Body: body, Duration: delay, Headers: map[string]string{"Content-Type": "text/html"}},
	}, nil
}

type reflectedXSSSurfaceClient struct{}

func (reflectedXSSSurfaceClient) Do(_ context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	u, _ := url.Parse(rawURL)
	value := u.Query().Get("q")
	if value == "" {
		values, _ := url.ParseQuery(string(body))
		value = values.Get("q")
	}
	if value == "" {
		value = requestHeader(headers, "X-Forwarded-For")
	}
	return httpclient.RequestResponse{
		Request: httpclient.RequestRecord{
			Method: method, URL: rawURL, Body: string(body), Headers: headers,
		},
		Response: httpclient.ResponseRecord{
			StatusCode: 200,
			Body:       `<html><body>` + value + `</body></html>`,
			Headers:    map[string]string{"Content-Type": "text/html"},
		},
	}, nil
}

func testRunner(t *testing.T, client HTTPDoer) *Runner {
	t.Helper()
	cfg := config.DefaultScanConfig()
	return NewRunner("scan-m", client, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil), nil, func(string, string, map[string]interface{}) error { return nil }, cfg)
}

type executedDOMRenderer struct{}

func (executedDOMRenderer) Render(context.Context, string) (string, error) {
	return `<html data-akca-xss="executed"></html>`, nil
}

func testTarget(payloads []payloadgen.Payload) ScanTarget {
	return ScanTarget{
		EndpointURL: "http://example.com/search", Method: "GET", Parameter: "q", Location: "query",
		Profile: reflection.ReflectionProfile{
			ReflectionKind: reflection.ReflectionRaw, Context: reflection.ContextHTML, Stable: true,
		},
		Payloads: payloadgen.GenerationResult{Payloads: payloads},
	}
}

func TestXSSReflectedAndDOM(t *testing.T) {
	client := &mockClient{responses: map[string]string{
		"akca-xss-base":              "results:",
		`"><svg/onload=alert(1)>`:    `results: "><svg/onload=alert(1)>`,
		verification.DOMXSSPayload(): `<html><script>window.__akca_xss_confirmed=true</script></html>`,
	}}
	payloads := []payloadgen.Payload{{Value: `"><svg/onload=alert(1)>`, VulnClass: "xss", Variant: "html_breakout"}}
	cfg := config.DefaultScanConfig()
	r := NewRunner("scan-m", client, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil), nil,
		func(string, string, map[string]interface{}) error { return nil }, cfg, WithBrowserRenderer(executedDOMRenderer{}))
	findings := r.runXSS(context.Background(), testTarget(payloads))
	if len(findings) == 0 {
		t.Fatal("expected xss finding")
	}
}

func TestXSSReflectedWithoutBrowserUsesExecutableReplayProof(t *testing.T) {
	payload := `"><svg/onload=alert(1)>`
	client := &mockClient{responses: map[string]string{
		"akca-xss-base":                "results:",
		payload:                        "results: " + payload,
		`<img src=x onerror=alert(1)>`: `results: <img src=x onerror=alert(1)>`,
		verification.DOMXSSPayload():   "results:",
		"__default__":                  "results:",
	}}
	payloads := []payloadgen.Payload{{
		Value: payload, VulnClass: "xss", Variant: "html_breakout", ExpectedSignal: "dom_mutation_svg",
	}}

	var verificationEvents []map[string]interface{}
	cfg := config.DefaultScanConfig()
	runner := NewRunner(
		"scan-m", client, scope.NewEngine(cfg), nil,
		verification.NewEngine(nil, func(eventType, _ string, eventPayload map[string]interface{}) error {
			if eventType == "finding_verified" {
				verificationEvents = append(verificationEvents, eventPayload)
			}
			return nil
		}),
		nil, func(string, string, map[string]interface{}) error { return nil }, cfg,
	)
	findings := runner.runXSS(context.Background(), testTarget(payloads))
	if len(findings) != 1 {
		t.Fatalf("expected one replay-proven reflected XSS finding, got %d; verification=%+v", len(findings), verificationEvents)
	}
	finding := findings[0]
	if finding.Evidence.Verification.ProofType != verification.ProofDifferentialReplay ||
		!finding.Evidence.Verification.ProofSatisfied {
		t.Fatalf("reflected XSS did not receive differential replay proof: %+v", finding.Evidence.Verification)
	}
	if finding.Confidence != verification.Confirmed && finding.Confidence != verification.HighConfidence {
		t.Fatalf("replay-proven XSS confidence = %s", finding.Confidence)
	}
}

func TestXSSReplayProofPreservesPOSTFormAndHeaderSurfaces(t *testing.T) {
	payload := payloadgen.Payload{
		Value: `"><svg/onload=alert(1)>`, VulnClass: "xss",
		Variant: "html_breakout", ExpectedSignal: "dom_mutation_svg",
	}
	tests := []struct {
		name     string
		target   ScanTarget
		location string
	}{
		{
			name: "form discovered from GET page",
			target: ScanTarget{
				EndpointURL: "http://example.com/submit", Method: "GET",
				Parameter: "q", Location: "form",
			},
			location: "form",
		},
		{
			name: "header on native POST endpoint",
			target: ScanTarget{
				EndpointURL: "http://example.com/actuator", Method: "POST",
				Parameter: "X-Forwarded-For", Location: "header",
			},
			location: "header",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			test.target.Profile = reflection.ReflectionProfile{
				ReflectionKind: reflection.ReflectionRaw, Context: reflection.ContextHTML, Stable: true,
			}
			test.target.Payloads = payloadgen.GenerationResult{Payloads: []payloadgen.Payload{payload}}
			findings := testRunner(t, reflectedXSSSurfaceClient{}).runXSS(context.Background(), test.target)
			if len(findings) != 1 {
				t.Fatalf("expected one reflected XSS finding, got %d", len(findings))
			}
			finding := findings[0]
			if finding.Evidence.Request.Method != "POST" || finding.Location != test.location {
				t.Fatalf("surface was not preserved: request=%+v location=%q", finding.Evidence.Request, finding.Location)
			}
			if finding.Evidence.Verification.ProofType != verification.ProofDifferentialReplay ||
				!finding.Evidence.Verification.ProofSatisfied {
				t.Fatalf("surface proof failed: %+v", finding.Evidence.Verification)
			}
		})
	}
}

func TestSQLiErrorBooleanTiming(t *testing.T) {
	client := &mockClient{
		responses: map[string]string{
			"akca-sqli-base": "items ok",
			`'`:              "mysql syntax error near",
			`' OR '1'='1`:    "many items listed",
			`' AND '1'='2`:   "items ok",
		},
		delays: map[string]time.Duration{
			`' OR SLEEP(2)--`: 1200 * time.Millisecond,
		},
	}
	payloads := []payloadgen.Payload{
		{Value: `'`, VulnClass: "sqli", Variant: "error", ExpectedSignal: "sql_error"},
		{Value: `' OR '1'='1`, VulnClass: "sqli", Variant: "boolean_true", ExpectedSignal: "content_change"},
		{Value: `' AND '1'='2`, VulnClass: "sqli", Variant: "boolean_false", ExpectedSignal: "content_unchanged_control", IsNegativeControl: true},
	}
	findings := testRunner(t, client).runSQLi(context.Background(), testTarget(payloads))
	if len(findings) == 0 {
		t.Fatal("expected sqli findings")
	}
}

func TestSSTIMathAndErrorTrace(t *testing.T) {
	client := &mockClient{responses: map[string]string{
		"akca-ssti-base": "hello",
		`{{11*13}}`:      "hello 143 world",
		`{{13*17}}`:      "hello 221 world",
		`${13*17}`:       "jinja2.exceptions.UndefinedError: boom",
	}}
	target := testTarget(nil)
	target.Payloads.Tech.Framework = "Jinja"
	findings := testRunner(t, client).runSSTI(context.Background(), target)
	if len(findings) < 1 {
		t.Fatalf("expected ssti findings, got %d", len(findings))
	}
}

func TestSSTINoFalsePositiveFromCommonNumber(t *testing.T) {
	client := &mockClient{responses: map[string]string{
		"akca-ssti-base": "price is 49 dollars",
		`{{11*13}}`:      "price is 49 dollars",
		`${13*17}`:       "price is 49 dollars",
		`<%= 11*13 %>`:   "price is 49 dollars",
	}}
	target := testTarget(nil)
	target.Payloads.Tech.Framework = "Jinja"
	findings := testRunner(t, client).runSSTI(context.Background(), target)
	if len(findings) != 0 {
		t.Fatalf("expected no ssti false positives, got %d", len(findings))
	}
}

func TestSSTICalculatorSurfaceIsRejected(t *testing.T) {
	client := &mockClient{responses: map[string]string{
		"__default__":  "calculator",
		`{{11*13}}`:    "result 143",
		`11*13`:        "result 143",
		`${13*17}`:     "result 221",
		`13*17`:        "result 221",
		`<%= 11*13 %>`: "result 143",
	}}
	target := testTarget(nil)
	target.Payloads.Tech.Framework = "Jinja"
	if findings := testRunner(t, client).runSSTI(context.Background(), target); len(findings) != 0 {
		t.Fatalf("generic calculator behavior must not be reported as SSTI, got %d", len(findings))
	}
}

func TestCommandInjectionSeparator(t *testing.T) {
	target := testTarget(nil)
	primarySeed, verificationSeed := commandCanarySeeds("scan-m", target)
	primary := commandCanaryProbe(payloadgen.Payload{}, false, primarySeed, "primary")
	verification := commandCanaryProbe(primary, false, verificationSeed, "verification")
	client := &mockClient{responses: map[string]string{
		"akca-cmd-base":    "output:",
		`|id`:              "uid=1000(root) gid=1000(root) groups=1000(root)",
		primary.Value:      "result " + commandExpectedMarker(primary),
		verification.Value: "result " + commandExpectedMarker(verification),
	}}
	findings := testRunner(t, client).runCommandInjection(context.Background(), target)
	if len(findings) == 0 {
		t.Fatal("expected command injection finding")
	}
}

func TestCommandInjectionRejectsReflectedCommerceHTML(t *testing.T) {
	findings := testRunner(t, commerceHTMLClient{}).runCommandInjection(context.Background(), testTarget(nil))
	if len(findings) != 0 {
		t.Fatalf("reflected URL and unrelated dynamic HTML identifiers must not confirm command injection, got %d", len(findings))
	}
}

type commerceHTMLClient struct{}

func (commerceHTMLClient) Do(_ context.Context, method, rawURL string, _ []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	u, _ := url.Parse(rawURL)
	reflected := u.Query().Get("q")
	body := fmt.Sprintf(`<!DOCTYPE html><html lang="tr-TR" dir="ltr"><head><meta charset="utf-8">`+
		`<div data-fluid="uid=674b8d5747-78dds"></div><script>const tracking="gid=61";</script>`+
		`<link rel="canonical" href="?merchantId=%s&boutiqueId=61">`+
		`<img src="https://cdn.dsmcdn.com/sfweb-browsing/images/footer-etbis.png"></html>`, url.QueryEscape(reflected))
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Headers: headers},
		Response: httpclient.ResponseRecord{StatusCode: 200, Body: body, Headers: map[string]string{"Content-Type": "text/html"}},
	}, nil
}

func TestNoSQLiAuthBypass(t *testing.T) {
	loginBodyBytes, _ := json.Marshal(map[string]interface{}{
		"username": map[string]string{"$ne": ""},
		"password": map[string]string{"$ne": ""},
	})
	loginBody := string(loginBodyBytes)
	controlBody := nosql.ControlBody("username")
	client := &nosqlBodyClient{responses: map[string]string{
		"akca-nosql-base": `{"error":"invalid credentials"}`,
		controlBody:       `{"error":"invalid credentials"}`,
		loginBody:         `{"access_token":"eyJhbGciOiJIUzI1NiJ9.abc","token_type":"bearer"}`,
	}}
	target := ScanTarget{
		EndpointURL: "http://example.com/api/login", Method: "POST", Parameter: "username",
		Profile: reflection.ReflectionProfile{ContentType: "application/json"},
	}
	findings := testRunner(t, client).runNoSQLi(context.Background(), target)
	if len(findings) == 0 {
		t.Fatal("expected nosql finding")
	}
}

type nosqlBodyClient struct {
	responses map[string]string
}

func (m *nosqlBodyClient) Do(_ context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	bodyStr := string(body)
	status := 200
	if bodyStr != "" {
		if resp, ok := m.responses[bodyStr]; ok {
			if strings.Contains(resp, "invalid credentials") {
				status = 401
			}
			return httpclient.RequestResponse{
				Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Body: bodyStr},
				Response: httpclient.ResponseRecord{StatusCode: status, Body: resp, Headers: map[string]string{"Content-Type": "application/json"}},
			}, nil
		}
	}
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Body: bodyStr},
		Response: httpclient.ResponseRecord{StatusCode: 404, Body: "not found"},
	}, nil
}

type nosqlBracketClient struct{}

func (nosqlBracketClient) Do(_ context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	u, _ := url.Parse(rawURL)
	status := 200
	responseBody := `{"items":[]}`
	for name := range u.Query() {
		if strings.Contains(name, "[$ne]") || strings.Contains(name, "[$gt]") {
			status = 500
			responseBody = `{"error":"MongoServerError: unknown operator $ne"}`
			break
		}
	}
	return httpclient.RequestResponse{
		Request: httpclient.RequestRecord{
			Method: method, URL: rawURL, Body: string(body), Headers: headers,
		},
		Response: httpclient.ResponseRecord{
			StatusCode: status, Body: responseBody,
			Headers: map[string]string{"Content-Type": "application/json"},
		},
	}, nil
}

func TestNoSQLiGETAPIBracketErrorHasCompleteProof(t *testing.T) {
	target := ScanTarget{
		EndpointURL: "http://example.com/api/search?username=alice",
		Method:      "GET",
		Parameter:   "username",
		Location:    "query",
	}
	findings := testRunner(t, nosqlBracketClient{}).runNoSQLi(context.Background(), target)
	if len(findings) == 0 {
		t.Fatal("expected reproduced bracket-operator NoSQL finding")
	}
	for _, finding := range findings {
		if finding.Evidence.Signal != "nosql_error_disclosure" {
			continue
		}
		if !finding.Evidence.Verification.ProofSatisfied ||
			!finding.Evidence.Verification.NegativeControlOK {
			t.Fatalf("NoSQL proof contract was incomplete: %+v", finding.Evidence.Verification)
		}
		if !strings.Contains(finding.Evidence.Payload.Value, "[$") {
			t.Fatalf("report evidence omitted the bracket payload: %+v", finding.Evidence.Payload)
		}
		return
	}
	t.Fatalf("NoSQL bracket finding missing from %+v", findings)
}

type bodyAwareClient struct {
	responses map[string]string
}

func (m *bodyAwareClient) Do(_ context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	bodyStr := string(body)
	if bodyStr != "" {
		if resp, ok := m.responses[bodyStr]; ok {
			return httpclient.RequestResponse{
				Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Body: bodyStr},
				Response: httpclient.ResponseRecord{StatusCode: 200, Body: resp, Headers: map[string]string{"Content-Type": "application/json"}},
			}, nil
		}
	}
	u, _ := url.Parse(rawURL)
	key := u.Query().Get("username")
	if key == "" {
		key = u.Query().Get("q")
	}
	resp := m.responses[key]
	if resp == "" {
		resp = m.responses["__default__"]
	}
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Body: bodyStr},
		Response: httpclient.ResponseRecord{StatusCode: 200, Body: resp, Headers: map[string]string{"Content-Type": "text/html"}},
	}, nil
}

func TestFindingPersistenceWithEvidence(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/mod.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_ = db.Migrate()
	client := &mockClient{responses: map[string]string{
		"akca-xss-base":           "x",
		`"><svg/onload=alert(1)>`: `"><svg/onload=alert(1)>`,
	}}
	cfg := config.DefaultScanConfig()
	runner := NewRunner("scan-p", client, scope.NewEngine(cfg), db, verification.NewEngine(db, nil), nil, func(string, string, map[string]interface{}) error { return nil }, cfg)
	payloads := []payloadgen.Payload{{Value: `"><svg/onload=alert(1)>`, VulnClass: "xss", Variant: "html_breakout"}}
	_ = runner.runXSS(context.Background(), testTarget(payloads))
}
