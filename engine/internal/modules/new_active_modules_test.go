package modules

import (
	"context"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/verification"
)

type activeTestClient struct {
	responses map[string]httpclient.ResponseRecord
}

func (c *activeTestClient) Do(_ context.Context, method, rawURL string, _ []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	key := method + " " + rawURL
	if subreq := headers["x-middleware-subrequest"]; subreq != "" {
		key += " [x-middleware-subrequest:" + subreq + "]"
	}

	if resp, ok := c.responses[key]; ok {
		return httpclient.RequestResponse{
			Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Headers: headers},
			Response: resp,
		}, nil
	}

	// Default 404
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Headers: headers},
		Response: httpclient.ResponseRecord{StatusCode: 404, Body: "not found", Headers: map[string]string{"Content-Type": "text/plain"}},
	}, nil
}

func newActiveRunner(t *testing.T, client HTTPDoer) *Runner {
	t.Helper()
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"example.com"}
	return NewRunner("scan-active-test", client, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil), nil, func(string, string, map[string]interface{}) error { return nil }, cfg)
}

func TestNginxOffBySlashTraversal(t *testing.T) {
	c := &activeTestClient{
		responses: map[string]httpclient.ResponseRecord{
			"GET https://example.com/static/app.js": {
				StatusCode: 200, Body: "console.log('app');", Headers: map[string]string{"Content-Type": "application/javascript"},
			},
			"GET https://example.com/static../admin": {
				StatusCode: 200, Body: "<h1>Admin Dashboard Secret Area</h1><p>Internal Server Settings</p>", Headers: map[string]string{"Content-Type": "text/html"},
			},
			"GET https://example.com/static/admin": {
				StatusCode: 404, Body: "Not Found", Headers: map[string]string{"Content-Type": "text/html"},
			},
			"GET https://example.com/admin": {
				StatusCode: 403, Body: "Access Denied", Headers: map[string]string{"Content-Type": "text/html"},
			},
		},
	}

	r := newActiveRunner(t, c)
	target := ScanTarget{EndpointURL: "https://example.com/static/app.js", Method: "GET"}
	findings := r.runNginxAlias(context.Background(), target)

	if len(findings) == 0 {
		t.Fatal("expected Nginx off-by-slash finding")
	}
	if findings[0].Severity != "high" {
		t.Fatalf("expected high severity, got %s", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Title, "Nginx Off-By-Slash") {
		t.Fatalf("unexpected title: %s", findings[0].Title)
	}
}

func TestNginxOffBySlashWildcardRejection(t *testing.T) {
	// SPA host where every path returns the same index.html
	spaHTML := "<html><body><div id='app'>SPA React Application Shell</div></body></html>"
	c := &activeTestClient{
		responses: map[string]httpclient.ResponseRecord{
			"GET https://example.com/static/app.js": {
				StatusCode: 200, Body: "console.log('app');", Headers: map[string]string{"Content-Type": "application/javascript"},
			},
		},
	}
	// For all unknown URLs, activeTestClient default is modified here to return 200 with spaHTML
	c.responses["GET https://example.com/static-akca-nonexistent-path-check-"] = httpclient.ResponseRecord{
		StatusCode: 200, Body: spaHTML, Headers: map[string]string{"Content-Type": "text/html"},
	}

	r := newActiveRunner(t, c)
	target := ScanTarget{EndpointURL: "https://example.com/static/app.js", Method: "GET"}
	findings := r.runNginxAlias(context.Background(), target)

	if len(findings) != 0 {
		t.Fatalf("expected wildcard SPA to be rejected with 0 findings, got %d", len(findings))
	}
}

func TestNextJSMiddlewareBypass(t *testing.T) {
	c := &activeTestClient{
		responses: map[string]httpclient.ResponseRecord{
			"GET https://example.com/api/admin/dashboard": {
				StatusCode: 403, Body: "Forbidden: Middleware Authentication Required", Headers: map[string]string{"Content-Type": "text/plain"},
			},
			"GET https://example.com/api/admin/dashboard [x-middleware-subrequest:middleware:middleware:middleware:middleware:middleware]": {
				StatusCode: 200, Body: "{\"secret\":\"admin-token\",\"users\":[{\"id\":1}]}", Headers: map[string]string{"Content-Type": "application/json"},
			},
		},
	}

	r := newActiveRunner(t, c)
	target := ScanTarget{EndpointURL: "https://example.com/api/admin/dashboard", Method: "GET"}
	findings := r.runNextJSBypass(context.Background(), target)

	if len(findings) == 0 {
		t.Fatal("expected Next.js middleware bypass finding")
	}
	if findings[0].Severity != "critical" {
		t.Fatalf("expected critical severity, got %s", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Title, "Next.js Middleware Authentication Bypass") {
		t.Fatalf("unexpected title: %s", findings[0].Title)
	}
}

func TestFrameworkDebugExposure(t *testing.T) {
	c := &activeTestClient{
		responses: map[string]httpclient.ResponseRecord{
			"GET https://example.com/home": {
				StatusCode: 200, Body: "<h1>Welcome</h1>", Headers: map[string]string{"Content-Type": "text/html"},
			},
			"GET https://example.com/console": {
				StatusCode: 200, Body: "<h1>Interactive Console</h1><p>Werkzeug powered</p>", Headers: map[string]string{"Content-Type": "text/html"},
			},
			"GET https://example.com/_ignition/health-check": {
				StatusCode: 200, Body: "{\"can_execute_commands\":true}", Headers: map[string]string{"Content-Type": "application/json"},
			},
		},
	}

	r := newActiveRunner(t, c)
	target := ScanTarget{EndpointURL: "https://example.com/home", Method: "GET"}
	findings := r.runFrameworkDebug(context.Background(), target)

	if len(findings) < 2 {
		t.Fatalf("expected at least 2 framework debug findings, got %d", len(findings))
	}
}

func TestIISDiscovery(t *testing.T) {
	c := &activeTestClient{
		responses: map[string]httpclient.ResponseRecord{
			"GET https://example.com/login.aspx": {
				StatusCode: 200, Body: "<html>Login</html>", Headers: map[string]string{"Content-Type": "text/html"},
			},
			"OPTIONS https://example.com/*~7*/.aspx": {
				StatusCode: 400, Body: "Bad Request: Invalid URL Pattern", Headers: map[string]string{"Content-Type": "text/html"},
			},
			"OPTIONS https://example.com/*~8*/.aspx": {
				StatusCode: 400, Body: "Bad Request: Invalid URL Pattern", Headers: map[string]string{"Content-Type": "text/html"},
			},
			"OPTIONS https://example.com/*~0*/.aspx": {
				StatusCode: 400, Body: "Bad Request: Invalid URL Pattern", Headers: map[string]string{"Content-Type": "text/html"},
			},
			"OPTIONS https://example.com/ZZZNONEXIST99*~1*/.aspx": {
				StatusCode: 400, Body: "Bad Request: Invalid URL Pattern", Headers: map[string]string{"Content-Type": "text/html"},
			},
			"OPTIONS https://example.com/QQQNOFILE88*~1*/.aspx": {
				StatusCode: 400, Body: "Bad Request: Invalid URL Pattern", Headers: map[string]string{"Content-Type": "text/html"},
			},
			"OPTIONS https://example.com/*~1*/.aspx": {
				StatusCode: 404, Body: "The resource cannot be found.", Headers: map[string]string{"Content-Type": "text/html"},
			},
			"OPTIONS https://example.com/ADMIN*~1*/.aspx": {
				StatusCode: 404, Body: "The resource cannot be found.", Headers: map[string]string{"Content-Type": "text/html"},
			},
			"OPTIONS https://example.com/ADMINZZZ99*~1*/.aspx": {
				StatusCode: 400, Body: "Bad Request: Invalid URL Pattern", Headers: map[string]string{"Content-Type": "text/html"},
			},
			"GET https://example.com/login.aspx::$DATA": {
				StatusCode: 200, Body: "<%@ Page Language=\"C#\" %>\n<script runat=\"server\">\nstring dbPass = \"secret123\";\n</script>", Headers: map[string]string{"Content-Type": "text/plain"},
			},
		},
	}

	r := newActiveRunner(t, c)
	target := ScanTarget{EndpointURL: "https://example.com/login.aspx", Method: "GET"}
	findings := r.runIISDiscovery(context.Background(), target)

	if len(findings) < 2 {
		t.Fatalf("expected 2 IIS findings (shortname + ::$DATA), got %d", len(findings))
	}
}
