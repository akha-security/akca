package modules

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/oast"
	"github.com/akha-security/akca/engine/internal/reflection"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/verification"
)

type stubOASTClient struct {
	url string
}

func (s *stubOASTClient) GenerateURL(payloadID, endpointURL, parameter, vulnClass string, findingID int64) (oast.GeneratedURL, error) {
	return oast.GeneratedURL{
		URL:              s.url,
		CorrelationToken: "akca-test-token",
		PayloadID:        payloadID,
	}, nil
}

func groupBRunner(t *testing.T, c HTTPDoer) *Runner {
	return groupBRunnerWithOAST(t, c, nil)
}

func groupBRunnerWithOAST(t *testing.T, c HTTPDoer, oastClient OASTClient) *Runner {
	t.Helper()
	cfg := config.DefaultScanConfig()
	cfg.EnableSecondOrderTracking = true
	return NewRunner("scan-b", c, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil), oastClient, func(string, string, map[string]interface{}) error { return nil }, cfg)
}

type groupBClient struct {
	responses map[string]string
	headers   map[string]map[string]string
	statuses  map[string]int
	calls     int
}

type flappingBFLAClient struct {
	controlCalls int
}

func (c *flappingBFLAClient) Do(_ context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	u, _ := url.Parse(rawURL)
	payload := u.Query().Get("q")
	status, responseBody := 200, "admin panel"
	if payload == "" {
		c.controlCalls++
		if c.controlCalls == 1 {
			status, responseBody = 403, "forbidden"
		}
	}
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Headers: headers, Body: string(body)},
		Response: httpclient.ResponseRecord{StatusCode: status, Body: responseBody},
	}, nil
}

func (m *groupBClient) lookup(rawURL string, body []byte, headers map[string]string) (string, int, map[string]string) {
	if h, ok := headers["Host"]; ok && h != "" {
		hostKey := "::host:" + h
		if resp, ok := m.responses[hostKey]; ok {
			return resp, m.status(hostKey), m.headers[hostKey]
		}
	}
	bodyStr := string(body)
	if bodyStr != "" {
		if resp, ok := m.responses[bodyStr]; ok {
			return resp, m.status(bodyStr), m.headers[bodyStr]
		}
		for k, v := range m.responses {
			if len(k) > 4 && strings.Contains(bodyStr, k) {
				return v, m.status(k), m.headers[k]
			}
		}
	}
	key := m.urlKey(rawURL)
	if resp, ok := m.responses[key]; ok {
		return resp, m.status(key), m.headers[key]
	}
	return m.responses["__default__"], m.status(key), nil
}

func (m *groupBClient) status(key string) int {
	if s, ok := m.statuses[key]; ok {
		return s
	}
	return 200
}

func (m *groupBClient) urlKey(rawURL string) string {
	u, _ := url.Parse(rawURL)
	q := u.Query()
	for _, k := range []string{"url", "q", "id", "redirect", "file", "path", "email", "view"} {
		if vals, ok := q[k]; ok && len(vals) > 0 {
			return vals[0]
		}
	}
	if u.Path != "" {
		return u.Path
	}
	return ""
}

func (m *groupBClient) Do(_ context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	m.calls++
	resp, status, extra := m.lookup(rawURL, body, headers)
	h := map[string]string{"Content-Type": "text/html"}
	for k, v := range extra {
		h[k] = v
	}
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Headers: headers, Body: string(body)},
		Response: httpclient.ResponseRecord{StatusCode: status, Body: resp, Headers: h},
	}, nil
}

func TestRunGroupBHonorsAllowedVulnerabilityClasses(t *testing.T) {
	c := &groupBClient{responses: map[string]string{"__default__": "ok"}}
	cfg := config.DefaultScanConfig()
	cfg.AllowedVulnerabilityClasses = []string{"xss"}
	r := NewRunner(
		"scan-b", c, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil),
		nil, func(string, string, map[string]interface{}) error { return nil }, cfg,
	)
	target := ScanTarget{EndpointURL: "http://example.com/api/fetch", Method: "GET", Parameter: "url"}
	findings, err := r.RunGroupB(context.Background(), []ScanTarget{target})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 || c.calls != 0 {
		t.Fatalf("filtered group B should not probe, findings=%d calls=%d", len(findings), c.calls)
	}
}

func TestSSRFMetadataSignal(t *testing.T) {
	c := &groupBClient{responses: map[string]string{
		"":                  "ok",
		"http://127.0.0.1/": "ok",
		"http://169.254.169.254/latest/meta-data/": "ami-id: ami-akca instance-id: i-akca",
		"http://2852039166/latest/meta-data/":      "ami-id: ami-akca instance-id: i-akca",
	}}
	target := ScanTarget{EndpointURL: "http://example.com/api/fetch", Method: "GET", Parameter: "url"}
	findings := groupBRunner(t, c).runSSRF(context.Background(), target)
	if len(findings) == 0 {
		t.Fatal("expected ssrf finding")
	}
	if findings[0].Severity != "critical" {
		t.Fatalf("reproduced structured SSRF evidence severity=%q, want critical", findings[0].Severity)
	}
}

func TestSSRFSkipsNonURLParameter(t *testing.T) {
	c := &groupBClient{responses: map[string]string{"__default__": "ok"}}
	target := ScanTarget{EndpointURL: "http://example.com/api/search", Method: "GET", Parameter: "q"}
	findings := groupBRunner(t, c).runSSRF(context.Background(), target)
	if len(findings) != 0 || c.calls != 0 {
		t.Fatalf("non-URL parameter must not be probed for SSRF, findings=%d calls=%d", len(findings), c.calls)
	}
}

func TestSSRFWeakParameterGetsOASTOnlyCoverage(t *testing.T) {
	oastURL := "http://weak-param.oast.test"
	c := &groupBClient{responses: map[string]string{
		oastURL: "ok",
	}}
	cfg := config.DefaultScanConfig()
	cfg.EnableOAST = true
	r := NewRunner(
		"scan-b", c, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil),
		&stubOASTClient{url: oastURL},
		func(string, string, map[string]interface{}) error { return nil },
		cfg,
	)
	target := ScanTarget{EndpointURL: "http://example.com/api/search", Method: "GET", Parameter: "q"}
	if findings := r.runSSRF(context.Background(), target); len(findings) != 0 {
		t.Fatalf("OAST delivery without a callback must remain a lead, got %d findings", len(findings))
	}
	if c.calls != 1 {
		t.Fatalf("weak parameter should receive exactly one OAST-only SSRF probe, calls=%d", c.calls)
	}
}

func TestSSRFDirectProofRequiresTwoProviderProbes(t *testing.T) {
	c := &groupBClient{responses: map[string]string{
		"": "ok",
		"http://169.254.169.254/latest/meta-data/": "ami-id: ami-akca instance-id: i-akca",
	}}
	target := ScanTarget{EndpointURL: "http://example.com/api/fetch", Method: "GET", Parameter: "url"}
	if findings := groupBRunner(t, c).runSSRF(context.Background(), target); len(findings) != 0 {
		t.Fatalf("one direct-response probe must not prove SSRF, got %d", len(findings))
	}
}

func TestSSRFOASTBlindProbe(t *testing.T) {
	oastURL := "http://abc123.oast.test"
	c := &groupBClient{responses: map[string]string{
		"http://example.com": "ok",
		"http://127.0.0.1/":  "ok",
		oastURL:              "ok",
	}}
	cfg := config.DefaultScanConfig()
	cfg.EnableOAST = true
	r := NewRunner(
		"scan-b", c, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil),
		&stubOASTClient{url: oastURL},
		func(string, string, map[string]interface{}) error { return nil },
		cfg,
	)
	target := ScanTarget{EndpointURL: "http://example.com/api/fetch", Method: "GET", Parameter: "url"}
	findings := r.runSSRF(context.Background(), target)
	if len(findings) != 0 {
		t.Fatalf("expected no SSRF finding before OAST callback, got %d", len(findings))
	}
}

func TestXXEOASTBlindProbe(t *testing.T) {
	oastURL := "http://abc123.oast.test"
	blindBody := `<!DOCTYPE foo [<!ENTITY % x SYSTEM "` + oastURL + `"><!ENTITY call SYSTEM "file:///nonexistent">%x;]><root/>`
	c := &groupBClient{responses: map[string]string{
		`<root>baseline</root>`: "baseline",
		blindBody:               "ok",
	}}
	cfg := config.DefaultScanConfig()
	cfg.EnableOAST = true
	r := NewRunner(
		"scan-b", c, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil),
		&stubOASTClient{url: oastURL},
		func(string, string, map[string]interface{}) error { return nil },
		cfg,
	)
	target := ScanTarget{
		EndpointURL: "http://example.com/xml", Method: "POST", Parameter: "body",
		Profile: reflection.ReflectionProfile{ContentType: "application/xml"},
	}
	findings := r.runXXE(context.Background(), target)
	for _, f := range findings {
		if f.Evidence.Signal == "blind_oast" {
			t.Fatal("blind XXE should not report before OAST callback")
		}
	}
}

func TestLFIOASTBlindProbe(t *testing.T) {
	oastURL := "http://abc123.oast.test"
	c := &groupBClient{responses: map[string]string{
		"index.html": "welcome",
		oastURL:      "welcome",
	}}
	cfg := config.DefaultScanConfig()
	cfg.EnableOAST = true
	r := NewRunner(
		"scan-b", c, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil),
		&stubOASTClient{url: oastURL},
		func(string, string, map[string]interface{}) error { return nil },
		cfg,
	)
	target := ScanTarget{EndpointURL: "http://example.com/view", Method: "GET", Parameter: "file"}
	findings := r.runLFI(context.Background(), target)
	for _, f := range findings {
		if f.Evidence.Signal == "rfi_oast" {
			t.Fatal("blind LFI should not report before OAST callback")
		}
	}
}

func TestBlindXSSOASTProbe(t *testing.T) {
	oastURL := "http://abc123.oast.test"
	c := &groupBClient{responses: map[string]string{
		"akca-blind-xss-base": "ok",
	}}
	cfg := config.DefaultScanConfig()
	cfg.EnableOAST = true
	r := NewRunner(
		"scan-b", c, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil),
		&stubOASTClient{url: oastURL},
		func(string, string, map[string]interface{}) error { return nil },
		cfg,
	)
	target := ScanTarget{
		EndpointURL: "http://example.com/page.html", Method: "GET", Parameter: "q",
		Profile: reflection.ReflectionProfile{ContentType: "text/html"},
	}
	findings := r.runBlindXSS(context.Background(), target)
	if len(findings) != 0 {
		t.Fatalf("expected no blind XSS finding before OAST callback, got %d", len(findings))
	}
}

func TestXXEClassicEntity(t *testing.T) {
	xxePayload := `<!DOCTYPE foo [<!ENTITY xxe "AKCA_XXE_TEST">]><root>&xxe;</root>`
	c := &groupBClient{responses: map[string]string{
		`<root>baseline</root>`: "baseline",
		xxePayload:              "AKCA_XXE_TEST",
	}}
	target := ScanTarget{EndpointURL: "http://example.com/xml", Method: "POST", Parameter: "body",
		Profile: reflection.ReflectionProfile{ContentType: "application/xml"}}
	findings := groupBRunner(t, c).runXXE(context.Background(), target)
	if len(findings) == 0 {
		t.Fatal("expected xxe finding")
	}
}

func TestLFITraversalSignal(t *testing.T) {
	c := &groupBClient{responses: map[string]string{
		"index.html":             "welcome",
		"../../../../etc/passwd": "root:x:0:0:root:/root:/bin/bash",
	}}
	target := ScanTarget{EndpointURL: "http://example.com/view", Method: "GET", Parameter: "file"}
	findings := groupBRunner(t, c).runLFI(context.Background(), target)
	if len(findings) != 0 {
		t.Fatal("single unreplayed file-content response must not prove LFI")
	}
}

func TestLFIWindowsTraversal(t *testing.T) {
	c := &groupBClient{responses: map[string]string{
		"index.html":                  "welcome",
		`..\..\..\..\windows\win.ini`: "[fonts]\r\n[extensions]\r\nfor 16-bit app support",
	}}
	target := ScanTarget{EndpointURL: "http://example.com/view", Method: "GET", Parameter: "file"}
	findings := groupBRunner(t, c).runLFI(context.Background(), target)
	if len(findings) != 0 {
		t.Fatal("single unreplayed Windows file-content response must not prove LFI")
	}
}

func TestLFITwoIndependentTraversalVariants(t *testing.T) {
	body := "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
	c := &groupBClient{responses: map[string]string{
		"index.html":                       "welcome",
		"../../../../etc/passwd":           body,
		"..%2f..%2f..%2f..%2fetc%2fpasswd": body,
	}}
	target := ScanTarget{EndpointURL: "http://example.com/view", Method: "GET", Parameter: "file"}
	findings := groupBRunner(t, c).runLFI(context.Background(), target)
	if len(findings) == 0 || !findings[0].Evidence.Verification.ProofSatisfied {
		t.Fatal("two traversal variants plus replay/control should prove LFI")
	}
}

func TestFileUploadExtensionBypass(t *testing.T) {
	c := &uploadProofClient{}
	target := ScanTarget{EndpointURL: "http://example.com/upload", Method: "POST", Parameter: "file"}
	cfg := config.DefaultScanConfig()
	cfg.FileUploadProofPolicies = []config.FileUploadProofPolicy{{
		ID: "test-cleanup", URLContains: "/upload", CleanupMethod: "DELETE", CleanupURL: "{{location}}",
	}}
	runner := NewRunner("scan-upload", c, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil),
		nil, func(string, string, map[string]interface{}) error { return nil }, cfg)
	findings := runner.runFileUpload(context.Background(), target)
	if len(findings) == 0 {
		t.Fatal("expected upload finding")
	}
}

type uploadProofClient struct {
	filename string
	marker   string
	deleted  bool
}

func (c *uploadProofClient) Do(_ context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	bodyText := string(body)
	if method == "POST" {
		filenamePattern := regexp.MustCompile(`filename="([^"]+)"`)
		markerPattern := regexp.MustCompile(`AKCA_UPLOAD_[A-Za-z0-9_-]+`)
		if match := filenamePattern.FindStringSubmatch(bodyText); len(match) == 2 {
			c.filename = match[1]
		}
		c.marker = markerPattern.FindString(bodyText)
		c.deleted = false
		return httpclient.RequestResponse{
			Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Headers: headers, Body: bodyText},
			Response: httpclient.ResponseRecord{StatusCode: 201, Body: `{"url":"/files/` + c.filename + `"}`},
		}, nil
	}
	if method == "DELETE" {
		c.deleted = true
		return httpclient.RequestResponse{
			Request:  httpclient.RequestRecord{Method: method, URL: rawURL},
			Response: httpclient.ResponseRecord{StatusCode: 204},
		}, nil
	}
	if c.deleted {
		return httpclient.RequestResponse{
			Request:  httpclient.RequestRecord{Method: method, URL: rawURL},
			Response: httpclient.ResponseRecord{StatusCode: 404, Body: "not found"},
		}, nil
	}
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: method, URL: rawURL},
		Response: httpclient.ResponseRecord{StatusCode: 200, Body: c.marker},
	}, nil
}

func TestIDOREnumerationRequiresTwoRoleProfiles(t *testing.T) {
	c := &groupBClient{responses: map[string]string{
		"1": `{"user":"self"}`,
		"2": `{"user":"other","email":"a@b.com"}`,
	}}
	target := ScanTarget{EndpointURL: "http://example.com/api/user", Method: "GET", Parameter: "id"}
	findings := groupBRunner(t, c).runIDOR(context.Background(), target)
	if len(findings) != 0 {
		t.Fatalf("single-session enumeration must not claim IDOR, got %d findings", len(findings))
	}
}

func TestBFLAFunctionBypass(t *testing.T) {
	c := &groupBClient{
		responses: map[string]string{"": "forbidden", "probe": "admin panel"},
		statuses:  map[string]int{"": 403, "probe": 200},
	}
	target := ScanTarget{EndpointURL: "http://example.com/admin/settings", Method: "GET", Parameter: "q"}
	findings := groupBRunner(t, c).runBFLA(context.Background(), target)
	if len(findings) != 0 {
		t.Fatal("single-role status transition must not prove BFLA")
	}
}

func TestBFLARejectsTransientStatusTransition(t *testing.T) {
	target := ScanTarget{EndpointURL: "http://example.com/admin/settings", Method: "GET", Parameter: "q"}
	findings := groupBRunner(t, &flappingBFLAClient{}).runBFLA(context.Background(), target)
	if len(findings) != 0 {
		t.Fatalf("transient 403 -> 200 transition must not prove BFLA, got %d findings", len(findings))
	}
}

func TestOpenRedirectSignal(t *testing.T) {
	c := &groupBClient{
		responses: map[string]string{
			"/":                         "ok",
			"https://evil.example/akca": "",
		},
		statuses: map[string]int{
			"/":                         200,
			"https://evil.example/akca": 302,
		},
		headers: map[string]map[string]string{
			"https://evil.example/akca": {"Location": "https://evil.example/akca"},
		},
	}
	target := ScanTarget{EndpointURL: "http://example.com/login", Method: "GET", Parameter: "redirect"}
	findings := groupBRunner(t, c).runOpenRedirect(context.Background(), target)
	if len(findings) == 0 {
		t.Fatal("expected open redirect finding")
	}
}

func TestHostHeaderInjection(t *testing.T) {
	c := &groupBClient{responses: map[string]string{
		"":                       "password reset sent",
		"::host:evil.akca.local": "reset link: https://evil.akca.local/reset",
	}}
	target := ScanTarget{EndpointURL: "http://example.com/reset", Method: "GET", Parameter: "email"}
	findings := groupBRunner(t, c).runHostHeader(context.Background(), target)
	if len(findings) == 0 {
		t.Fatal("expected host header finding")
	}
}

func TestSecondOrderTracking(t *testing.T) {
	c := &groupBClient{responses: map[string]string{
		"": "page with akca-stored-q-scan-b marker",
	}}
	r := groupBRunner(t, c)
	r.stored["http://example.com/post::q"] = "akca-stored-q-scan-b"
	target := ScanTarget{EndpointURL: "http://example.com/profile", Method: "GET", Parameter: "view"}
	findings := r.runSecondOrder(context.Background(), target)
	if len(findings) != 0 {
		t.Fatal("stored marker presence alone must not prove second-order execution")
	}
}

func TestModuleManifestsPresent(t *testing.T) {
	if len(GroupBRegistry) < 9 {
		t.Fatalf("expected 9 group B modules, got %d", len(GroupBRegistry))
	}
	for _, m := range GroupBRegistry {
		if m.Manifest.Name == "" || m.Manifest.Description == "" {
			t.Fatalf("invalid manifest: %+v", m)
		}
	}
}
