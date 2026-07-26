package modules

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/graphqlattack"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/reflection"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/testfixtures"
	"github.com/akha-security/akca/engine/internal/verification"
)

type groupDClient struct {
	responses map[string]string
	headers   map[string]map[string]string
	statuses  map[string]int
}

func (m *groupDClient) lookup(rawURL string, body []byte, headers map[string]string) (string, int, map[string]string) {
	bodyStr := string(body)
	if bodyStr != "" {
		if resp, ok := m.responses[bodyStr]; ok {
			return resp, m.status(bodyStr), m.headers[bodyStr]
		}
	}
	for hk, hv := range headers {
		key := "hdr:" + strings.ToLower(hk) + ":" + hv
		if resp, ok := m.responses[key]; ok {
			return resp, m.status(key), m.headers[key]
		}
	}
	key := m.urlKey(rawURL)
	pathKey := ""
	if u, err := url.Parse(rawURL); err == nil {
		pathKey = u.Path
	}
	resp, ok := m.responses[key]
	if !ok && pathKey != "" {
		resp, ok = m.responses[pathKey]
		key = pathKey
	}
	if !ok {
		resp, ok = m.responses[rawURL]
		if ok {
			key = rawURL
		}
	}
	if !ok {
		resp = m.responses["__default__"]
	}
	extra := m.headers[key]
	if extra == nil && pathKey != "" {
		extra = m.headers[pathKey]
	}
	return resp, m.status(key), extra
}

func (m *groupDClient) status(key string) int {
	if s, ok := m.statuses[key]; ok {
		return s
	}
	return 200
}

func (m *groupDClient) urlKey(rawURL string) string {
	u, _ := url.Parse(rawURL)
	q := u.Query()
	for _, k := range []string{"q", "price", "claim", "msg", "role", "x"} {
		if vals, ok := q[k]; ok && len(vals) > 0 {
			if len(vals) > 1 {
				return vals[0] + "+" + vals[1]
			}
			return vals[0]
		}
	}
	return u.Path
}

func (m *groupDClient) Do(_ context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	resp, status, extra := m.lookup(rawURL, body, headers)
	h := map[string]string{"Content-Type": "text/html", "Server": "Apache/2.4.49"}
	for k, v := range extra {
		h[k] = v
	}
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Headers: headers, Body: string(body)},
		Response: httpclient.ResponseRecord{StatusCode: status, Body: resp, Headers: h},
	}, nil
}

func groupDRunner(t *testing.T, c *groupDClient, opts ...RunnerOption) *Runner {
	t.Helper()
	cfg := config.DefaultScanConfig()
	cfg.EnableBusinessLogicChecks = true
	cfg.EnableRaceConditionTesting = true
	return NewRunner("scan-d", c, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil), nil, func(string, string, map[string]interface{}) error { return nil }, cfg, opts...)
}

type tlsInspectorFunc func(context.Context, string) (TLSInspection, error)

func (f tlsInspectorFunc) Inspect(ctx context.Context, rawURL string) (TLSInspection, error) {
	return f(ctx, rawURL)
}

type websocketProberFunc func(context.Context, string, string) (httpclient.RequestResponse, error)

func (f websocketProberFunc) Probe(ctx context.Context, rawURL, payload string) (httpclient.RequestResponse, error) {
	return f(ctx, rawURL, payload)
}

type smugglingProberFunc func(context.Context, string, string) (SmugglingProbeResult, error)

func (f smugglingProberFunc) Probe(ctx context.Context, rawURL, variant string) (SmugglingProbeResult, error) {
	return f(ctx, rawURL, variant)
}

func TestSecurityHeadersMissing(t *testing.T) {
	c := &groupDClient{responses: map[string]string{"": "ok"}, headers: map[string]map[string]string{"": {}}}
	target := ScanTarget{EndpointURL: "http://example.com/", Method: "GET", Parameter: "q"}
	findings := groupDRunner(t, c).runSecurityHeaders(context.Background(), target)
	if len(findings) == 0 {
		t.Fatal("expected security header findings")
	}
}

func TestTLSMisconfiguration(t *testing.T) {
	c := &groupDClient{responses: map[string]string{"": "ok"}}
	inspector := tlsInspectorFunc(func(context.Context, string) (TLSInspection, error) {
		return TLSInspection{Signals: []string{"weak_protocol"}, Protocol: "TLS 1.0", Cipher: "TLS_RSA_WITH_AES_128_CBC_SHA"}, nil
	})
	target := ScanTarget{EndpointURL: "https://example.com/", Method: "GET", Parameter: "q"}
	findings := groupDRunner(t, c, WithTLSInspector(inspector)).runTLSMisconfig(context.Background(), target)
	if len(findings) == 0 {
		t.Fatal("expected tls findings")
	}
}

func TestVulnerableComponentsCVE(t *testing.T) {
	c := &groupDClient{responses: map[string]string{"": "powered by log4j 2.14.1"}}
	target := ScanTarget{EndpointURL: "http://example.com/api", Method: "GET", Parameter: "q"}
	findings := groupDRunner(t, c).runVulnerableComponents(context.Background(), target)
	if len(findings) != 0 {
		t.Fatal("component inventory must not duplicate known_cve findings")
	}
}

func TestKnownCVEDetection(t *testing.T) {
	c := &groupDClient{responses: map[string]string{"": "log4j-core 2.14.1"}}
	target := ScanTarget{EndpointURL: "http://example.com/", Method: "GET", Parameter: "q"}
	findings := groupDRunner(t, c).runKnownCVE(context.Background(), target)
	if len(findings) != 0 {
		t.Fatal("banner-only version text must not prove a known CVE")
	}
}

func TestSensitiveDataExposure(t *testing.T) {
	c := &groupDClient{responses: map[string]string{
		"akca-sensitive-base": "public profile page",
		"":                    "patient ssn 123-45-6789",
	}}
	target := ScanTarget{EndpointURL: "http://example.com/profile", Method: "GET", Parameter: "q"}
	findings := groupDRunner(t, c).runSensitiveData(context.Background(), target)
	if len(findings) == 0 {
		t.Fatal("expected sensitive data finding")
	}
}

func TestSecretExposure(t *testing.T) {
	c := &groupDClient{responses: map[string]string{
		"akca-secret-base": "config page",
		"":                 `api_key="` + testfixtures.GitHubToken() + `"`,
	}}
	target := ScanTarget{EndpointURL: "http://example.com/config", Method: "GET", Parameter: "q"}
	findings := groupDRunner(t, c).runSecretExposure(context.Background(), target)
	if len(findings) == 0 {
		t.Fatal("expected secret exposure finding")
	}
}

func TestCICDExposure(t *testing.T) {
	c := &groupDClient{
		responses: map[string]string{"/.git/HEAD": "ref: refs/heads/main"},
		statuses:  map[string]int{"/.git/HEAD": 200},
	}
	target := ScanTarget{EndpointURL: "http://example.com/jenkins/app", Method: "GET", Parameter: "q"}
	findings := groupDRunner(t, c).runGitDeepRecovery(context.Background(), target)
	if len(findings) == 0 {
		t.Fatal("expected cicd exposure finding")
	}
}

func TestGraphQLIntrospection(t *testing.T) {
	c := &groupDClient{responses: map[string]string{
		`{"query":"{user { __typename } }"}`:                          `{"data":{"user":{"__typename":"User"}}}`,
		`{"query":"{ __schema { types { name fields { name } } } }"}`: `{"data":{"__schema":{"types":[{"name":"User","fields":[{"name":"password"}]}]}}}`,
	}}
	target := ScanTarget{
		EndpointURL: "http://example.com/graphql", Method: "POST", Parameter: "body",
		Profile: reflection.ReflectionProfile{ContentType: "application/json"},
	}
	findings := groupDRunner(t, c).runGraphQL(context.Background(), target)
	if len(findings) != 0 {
		t.Fatal("introspection availability alone must not be reported as a vulnerability")
	}
}

func TestScriptSourceBrokenCDN(t *testing.T) {
	c := &groupDClient{responses: map[string]string{
		"":                              `<html><script src="https://cdn.vendor.com/app.js"></script></html>`,
		"https://cdn.vendor.com/app.js": "There isn't a GitHub Pages site here.",
	}}
	target := ScanTarget{
		EndpointURL: "http://example.com/page", Method: "GET", Parameter: "q",
		Profile: reflection.ReflectionProfile{ContentType: "text/html"},
	}
	findings := groupDRunner(t, c).runScriptSource(context.Background(), target)
	if len(findings) == 0 {
		t.Fatal("expected script source finding")
	}
}

func TestGraphQLBatchAbuse(t *testing.T) {
	batch := graphqlattack.BuildBatchProbe(20)
	inversion := graphqlattack.BuildTypeInversionProbes("user")[0]
	c := &groupDClient{responses: map[string]string{
		`{"query":"{user { __typename } }"}`: `{"data":{"user":{"__typename":"User"}}}`,
		inversion.Body:                       `{"errors":[{"message":"expected type Int"}]}`,
		batch.Body:                           strings.Repeat(`{"data":{"__typename":"Query"}}`, 20),
	}}
	target := ScanTarget{
		EndpointURL: "http://example.com/graphql", Method: "POST", Parameter: "user",
		Profile: reflection.ReflectionProfile{ContentType: "application/json"},
	}
	baseline := httpclient.RequestResponse{Response: httpclient.ResponseRecord{Body: `{"data":{"user":{"__typename":"User"}}}`}}
	findings := groupDRunner(t, c).runGraphQLAbuse(context.Background(), target, baseline, "user")
	if len(findings) == 0 {
		t.Fatal("expected graphql batch or abuse finding")
	}
}

func TestGraphQLUsesIntrospectionFieldsForAbuseProbes(t *testing.T) {
	c := &groupDClient{responses: map[string]string{
		graphQLIntrospectionQuery:                           `{"data":{"__schema":{"types":[{"name":"Query","fields":[{"name":"account"}]}]}}}`,
		`{"query":"{account { __typename } }"}`:             `{"data":{"account":{"__typename":"Account"}}}`,
		graphqlattack.BuildSuggestionsProbe("account").Body: `{"errors":[{"message":"Cannot query field account_nonexistent_field_xyz on type Query. Did you mean account?"}]}`,
	}}
	target := ScanTarget{EndpointURL: "http://example.com/graphql", Method: "POST", Parameter: "body"}
	findings := groupDRunner(t, c).runGraphQL(context.Background(), target)
	if len(findings) == 0 {
		t.Fatal("expected graphql probes to use introspected field candidates")
	}
}

func TestWebSocketDeepTesting(t *testing.T) {
	c := &groupDClient{responses: map[string]string{}}
	prober := websocketProberFunc(func(_ context.Context, rawURL, payload string) (httpclient.RequestResponse, error) {
		body := "ok"
		if payload == "' OR 1=1--" {
			body = "mysql syntax error near"
		}
		return httpclient.RequestResponse{
			Request:  httpclient.RequestRecord{Method: "GET", URL: rawURL, Body: payload},
			Response: httpclient.ResponseRecord{StatusCode: 101, Body: body},
		}, nil
	})
	target := ScanTarget{EndpointURL: "http://example.com/ws/socket", Method: "GET", Parameter: "msg"}
	findings := groupDRunner(t, c, WithWebSocketProber(prober)).runWebSocket(context.Background(), target)
	if len(findings) == 0 {
		t.Fatal("expected websocket finding")
	}
}

func TestCloudStorageExposure(t *testing.T) {
	c := &groupDClient{
		responses: map[string]string{
			"https://example.s3.amazonaws.com/": "<ListBucketResult><Contents><Key>secret</Key></Contents></ListBucketResult>",
		},
		statuses: map[string]int{"https://example.s3.amazonaws.com/": 200},
	}
	target := ScanTarget{EndpointURL: "https://example.s3.amazonaws.com/", Method: "GET", Parameter: "q"}
	findings := groupDRunner(t, c).runCloudStorage(context.Background(), target)
	if len(findings) == 0 {
		t.Fatal("expected cloud storage finding")
	}
}

func TestClientSSTI(t *testing.T) {
	c := &groupDClient{responses: map[string]string{"akca-base": "base", "__default__": "template"}}
	renderer := clientSSTIRenderer{}
	target := ScanTarget{
		EndpointURL: "http://example.com/render", Method: "GET", Parameter: "q",
		Profile: reflection.ReflectionProfile{ContentType: "text/html"},
	}
	findings := groupDRunner(t, c, WithBrowserRenderer(renderer)).runClientSSTI(context.Background(), target)
	if len(findings) == 0 {
		t.Fatal("expected client ssti finding")
	}
}

func TestRequestSmugglingSignal(t *testing.T) {
	c := &groupDClient{responses: map[string]string{}}
	prober := smugglingProberFunc(func(_ context.Context, rawURL, variant string) (SmugglingProbeResult, error) {
		control := httpclient.RequestResponse{
			Request:  httpclient.RequestRecord{Method: "POST", URL: rawURL, Body: "valid pipeline"},
			Response: httpclient.ResponseRecord{StatusCode: 200, Body: "two normal responses"},
		}
		attack := httpclient.RequestResponse{
			Request:  httpclient.RequestRecord{Method: "POST", URL: rawURL, Body: "raw conflicting framing"},
			Response: httpclient.ResponseRecord{StatusCode: 200, Body: "response queue differential"},
		}
		return SmugglingProbeResult{
			Confirmed: variant == "cl_te", Signal: variant,
			Reason:   "repeated raw HTTP/1.1 response queue differential",
			Exchange: attack, Control: control, Attempts: []httpclient.RequestResponse{attack, attack},
		}, nil
	})
	target := ScanTarget{EndpointURL: "http://example.com/", Method: "POST", Parameter: "q"}
	findings := groupDRunner(t, c, WithSmugglingProber(prober)).runSmuggling(context.Background(), target)
	if len(findings) == 0 {
		t.Fatal("expected smuggling finding")
	}
}

func TestRequestSmugglingSkipsGETSurface(t *testing.T) {
	c := &groupDClient{responses: map[string]string{}}
	target := ScanTarget{EndpointURL: "http://example.com/", Method: "GET", Parameter: "q"}
	findings := groupDRunner(t, c).runSmuggling(context.Background(), target)
	if len(findings) != 0 {
		t.Fatalf("expected GET smuggling surface to be skipped, got %d", len(findings))
	}
}

func TestPrototypePollution(t *testing.T) {
	c := &groupDClient{responses: map[string]string{
		`{"name":"akca"}`:                 `{"ok":true}`,
		`{"__proto__":{"polluted":true}}`: `{"polluted":true}`,
	}}
	target := ScanTarget{
		EndpointURL: "http://example.com/api", Method: "POST", Parameter: "body",
		Profile: reflection.ReflectionProfile{ContentType: "application/json"},
	}
	findings := groupDRunner(t, c).runPrototypePollution(context.Background(), target)
	if len(findings) != 0 {
		t.Fatal("a reflected polluted key without cross-request state proof must not be reported")
	}
}

func TestLDAPXPathHeaderInjection(t *testing.T) {
	c := &groupDClient{
		responses: map[string]string{
			"*)(uid=*":                            "ldap matched users",
			"hdr:x-test:test\r\nX-Injected: true": "ok",
		},
		headers: map[string]map[string]string{
			"hdr:x-test:test\r\nX-Injected: true": {"X-Injected": "true"},
		},
	}
	target := ScanTarget{EndpointURL: "http://example.com/search", Method: "GET", Parameter: "q"}
	findings := groupDRunner(t, c).runLDAPXPathInjection(context.Background(), target)
	if len(findings) == 0 {
		t.Fatal("expected ldap/xpath/header injection finding")
	}
}

func TestCRLFInjectionRunsAsFirstClassModule(t *testing.T) {
	payload := "\r\nX-Akca-CRLF: akca-crlf-q"
	c := &groupDClient{
		responses: map[string]string{
			"__default__": "ok",
			payload:       "ok",
		},
		headers: map[string]map[string]string{
			payload: {"X-Akca-CRLF": "akca-crlf-q"},
		},
	}
	target := ScanTarget{EndpointURL: "http://example.com/search", Method: "GET", Parameter: "q", Location: "query"}
	r := groupDRunner(t, c)
	findings := r.runCRLF(context.Background(), target)
	if len(findings) == 0 || findings[0].VulnClass != "crlf" {
		t.Fatalf("expected first-class CRLF finding, got %+v", findings)
	}
}

func TestDebugAdminExposure(t *testing.T) {
	c := &groupDClient{responses: map[string]string{"/debug": "stack trace at admin panel"}}
	target := ScanTarget{EndpointURL: "http://example.com/debug", Method: "GET", Parameter: "x"}
	findings := groupDRunner(t, c).runDebugAdmin(context.Background(), target)
	if len(findings) == 0 {
		t.Fatal("expected debug admin finding")
	}
}

func TestBusinessLogicSignal(t *testing.T) {
	c := &groupDClient{responses: map[string]string{
		"100": "total: 100",
		"0":   "order confirmed total: 0",
	}}
	target := ScanTarget{EndpointURL: "http://example.com/checkout", Method: "GET", Parameter: "price"}
	findings := groupDRunner(t, c).runBusinessLogic(context.Background(), target)
	if len(findings) != 0 {
		t.Fatal("business-logic lead must remain manual until a state invariant is proven")
	}
}

func TestRaceConditionDetection(t *testing.T) {
	c := &groupDClient{responses: map[string]string{"bonus": "bonus claimed success"}}
	target := ScanTarget{EndpointURL: "http://example.com/redeem", Method: "GET", Parameter: "claim"}
	findings := groupDRunner(t, c).runRaceCondition(context.Background(), target)
	if len(findings) != 0 {
		t.Fatal("race-condition lead must remain manual until an atomicity violation is proven")
	}
}

func TestAPIVersioningDiscovery(t *testing.T) {
	c := &groupDClient{
		responses: map[string]string{"/api/v2": `{"version":"v2"}`},
		statuses:  map[string]int{"/api/v2": 200},
	}
	target := ScanTarget{EndpointURL: "http://example.com/api", Method: "GET", Parameter: "q"}
	findings := groupDRunner(t, c).runAPIVersioning(context.Background(), target)
	if len(findings) == 0 {
		t.Fatal("expected api versioning finding")
	}
}

func TestRunGroupDCanRunCICDExposureByAllowList(t *testing.T) {
	c := &groupDClient{
		responses: map[string]string{"/.env": "API_KEY=secretvalue123"},
		statuses:  map[string]int{"/.env": 200},
	}
	cfg := config.DefaultScanConfig()
	cfg.AllowedVulnerabilityClasses = []string{"cicd_exposure"}
	r := NewRunner("scan-d", c, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil), nil, func(string, string, map[string]interface{}) error { return nil }, cfg)
	target := ScanTarget{EndpointURL: "http://example.com/jenkins", Method: "GET", Parameter: "q"}
	findings, err := r.RunGroupD(context.Background(), []ScanTarget{target})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected cicd_exposure to run independently from git_recovery")
	}
	for _, f := range findings {
		if f.VulnClass != "cicd_exposure" {
			t.Fatalf("unexpected finding class with allow list: %s", f.VulnClass)
		}
	}
}

func TestGroupDManifestsPresent(t *testing.T) {
	if len(GroupDRegistry) < 20 {
		t.Fatalf("expected 20 group D modules, got %d", len(GroupDRegistry))
	}
}

type clientSSTIRenderer struct{}

func (clientSSTIRenderer) Render(_ context.Context, rawURL string) (string, error) {
	decoded, _ := url.QueryUnescape(rawURL)
	re := regexp.MustCompile(`akca-csti-[A-Za-z0-9_-]+`)
	marker := re.FindString(decoded)
	return `<html data-akca-csti="` + marker + `"></html>`, nil
}
