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

func newActiveRunnerWithDomains(t *testing.T, client HTTPDoer, domains ...string) *Runner {
	t.Helper()
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = append([]string{"example.com"}, domains...)
	return NewRunner("scan-active-test", client, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil), nil, func(string, string, map[string]interface{}) error { return nil }, cfg)
}

func TestFirebaseMisconfig(t *testing.T) {
	c := &activeTestClient{
		responses: map[string]httpclient.ResponseRecord{
			"GET https://example.com/app.js": {
				StatusCode: 200, Body: `const db = "https://my-test-app.firebaseio.com"; const storage = "my-test-app.appspot.com";`, Headers: map[string]string{"Content-Type": "application/javascript"},
			},
			"GET https://my-test-app.firebaseio.com/.json?shallow=true": {
				StatusCode: 200, Body: `{"users": true, "config": true}`, Headers: map[string]string{"Content-Type": "application/json"},
			},
			"GET https://firebasestorage.googleapis.com/v0/b/my-test-app.appspot.com/o/": {
				StatusCode: 200, Body: `{"items":[{"name":"avatars/user1.png","bucket":"my-test-app.appspot.com"}]}`, Headers: map[string]string{"Content-Type": "application/json"},
			},
		},
	}

	r := newActiveRunnerWithDomains(t, c, "*.firebaseio.com", "*.googleapis.com")
	target := ScanTarget{EndpointURL: "https://example.com/app.js", Method: "GET"}
	findings := r.runFirebaseMisconfig(context.Background(), target)

	if len(findings) < 2 {
		t.Fatalf("expected at least 2 Firebase findings (RTDB + Storage), got %d", len(findings))
	}
}

func TestSpringCloudJolokia(t *testing.T) {
	c := &activeTestClient{
		responses: map[string]httpclient.ResponseRecord{
			"GET https://example.com/": {
				StatusCode: 200, Body: `<html>Home</html>`, Headers: map[string]string{"Content-Type": "text/html"},
			},
			"GET https://example.com/application/default": {
				StatusCode: 200, Body: `{"name":"application","profiles":["default"],"propertySources":[{"name":"applicationConfig","source":{"db.password":"secret"}}]}`, Headers: map[string]string{"Content-Type": "application/json"},
			},
			"GET https://example.com/actuator/jolokia": {
				StatusCode: 200, Body: `{"request":{"type":"version"},"value":{"agent":"1.6.2","protocol":"7.2"},"status":200}`, Headers: map[string]string{"Content-Type": "application/json"},
			},
		},
	}

	r := newActiveRunner(t, c)
	target := ScanTarget{EndpointURL: "https://example.com/", Method: "GET"}
	findings := r.runSpringCloudJolokia(context.Background(), target)

	if len(findings) < 2 {
		t.Fatalf("expected 2 findings (Spring Cloud Config + Jolokia), got %d", len(findings))
	}
}

func TestSaaSExposure(t *testing.T) {
	c := &activeTestClient{
		responses: map[string]httpclient.ResponseRecord{
			"GET https://example.com/": {
				StatusCode: 200, Body: `<html>Home</html>`, Headers: map[string]string{"Content-Type": "text/html"},
			},
			"GET https://example.com/api/now/table/sys_user?sysparm_limit=2": {
				StatusCode: 200, Body: `{"result":[{"sys_id":"123","user_name":"admin"}]}`, Headers: map[string]string{"Content-Type": "application/json"},
			},
		},
	}

	r := newActiveRunner(t, c)
	target := ScanTarget{EndpointURL: "https://example.com/", Method: "GET"}
	findings := r.runSaaSExposure(context.Background(), target)

	if len(findings) == 0 {
		t.Fatal("expected ServiceNow exposure finding")
	}
	if !strings.Contains(findings[0].Title, "ServiceNow") {
		t.Fatalf("unexpected title: %s", findings[0].Title)
	}
}

func TestCPDoS(t *testing.T) {
	poisonedURLs := make(map[string]bool)
	c := &activeDynamicClient{
		handler: func(method, rawURL string, headers map[string]string) httpclient.ResponseRecord {
			if headers["X-HTTP-Method-Override"] != "" {
				poisonedURLs[rawURL] = true
				return httpclient.ResponseRecord{
					StatusCode: 400,
					Body:       "Bad Request: Method Override Blocked",
					Headers: map[string]string{
						"Cache-Control":   "public, max-age=3600",
						"CF-Cache-Status": "MISS",
					},
				}
			}
			if poisonedURLs[rawURL] {
				return httpclient.ResponseRecord{
					StatusCode: 400,
					Body:       "Bad Request: Method Override Blocked (From CDN Cache)",
					Headers: map[string]string{
						"Cache-Control":   "public, max-age=3600",
						"CF-Cache-Status": "HIT",
						"Age":             "5",
					},
				}
			}
			return httpclient.ResponseRecord{
				StatusCode: 200,
				Body:       "Normal Page Content",
				Headers: map[string]string{
					"Cache-Control":   "public, max-age=3600",
					"CF-Cache-Status": "MISS",
				},
			}
		},
	}

	r := newActiveRunner(t, c)
	target := ScanTarget{EndpointURL: "https://example.com/item", Method: "GET"}
	findings := r.runCPDoS(context.Background(), target)

	if len(findings) == 0 {
		t.Fatal("expected CPDoS finding")
	}
	if !strings.Contains(findings[0].Title, "CPDoS") {
		t.Fatalf("unexpected title: %s", findings[0].Title)
	}
}

func TestProxyPathConfusion(t *testing.T) {
	c := &activeTestClient{
		responses: map[string]httpclient.ResponseRecord{
			"GET https://example.com/admin": {
				StatusCode: 403, Body: "Access Denied: Admin Area Forbidden", Headers: map[string]string{"Content-Type": "text/html"},
			},
			"GET https://example.com/..;/admin": {
				StatusCode: 200, Body: "<h1>Admin Dashboard Secret Area</h1>", Headers: map[string]string{"Content-Type": "text/html"},
			},
		},
	}

	r := newActiveRunner(t, c)
	target := ScanTarget{EndpointURL: "https://example.com/admin", Method: "GET"}
	findings := r.runProxyPathConfusion(context.Background(), target)

	if len(findings) == 0 {
		t.Fatal("expected Proxy Path Confusion finding")
	}
	if !strings.Contains(findings[0].Title, "Reverse Proxy Path Confusion") {
		t.Fatalf("unexpected title: %s", findings[0].Title)
	}
}

func TestCrossSiteWebSocketHijacking(t *testing.T) {
	c := &activeDynamicClient{
		handler: func(method, rawURL string, headers map[string]string) httpclient.ResponseRecord {
			if headers["Upgrade"] == "websocket" && strings.Contains(headers["Origin"], "attacker") {
				return httpclient.ResponseRecord{
					StatusCode: 101,
					Body:       "Switching Protocols",
					Headers:    map[string]string{"Upgrade": "websocket", "Connection": "Upgrade"},
				}
			}
			return httpclient.ResponseRecord{
				StatusCode: 400,
				Body:       "Bad Request: WebSocket Upgrade Required",
			}
		},
	}

	r := newActiveRunner(t, c)
	target := ScanTarget{EndpointURL: "https://example.com/ws/chat", Method: "GET"}
	findings := r.runCrossSiteWebSocketHijack(context.Background(), target)

	if len(findings) == 0 {
		t.Fatal("expected CSWSH finding")
	}
	if !strings.Contains(findings[0].Title, "Cross-Site WebSocket Hijacking") {
		t.Fatalf("unexpected title: %s", findings[0].Title)
	}
}

func TestPDFInjection(t *testing.T) {
	c := &activeDynamicClient{
		handler: func(method, rawURL string, headers map[string]string) httpclient.ResponseRecord {
			if strings.Contains(rawURL, "passwd") || strings.Contains(rawURL, "etc") {
				return httpclient.ResponseRecord{
					StatusCode: 200,
					Body:       "%PDF-1.4\nroot:x:0:0:root:/root:/bin/bash\n%%EOF",
					Headers:    map[string]string{"Content-Type": "application/pdf"},
				}
			}
			return httpclient.ResponseRecord{
				StatusCode: 200,
				Body:       "%PDF-1.4\nNormal invoice content\n%%EOF",
				Headers:    map[string]string{"Content-Type": "application/pdf"},
			}
		},
	}

	r := newActiveRunner(t, c)
	target := ScanTarget{EndpointURL: "https://example.com/export?pdf_template=default", Parameter: "pdf_template", Method: "GET"}
	findings := r.runPDFInjection(context.Background(), target)

	if len(findings) == 0 {
		t.Fatal("expected PDF injection LFI finding")
	}
	if findings[0].Severity != "critical" {
		t.Fatalf("expected critical severity, got %s", findings[0].Severity)
	}
}

func TestJSONPCallback(t *testing.T) {
	c := &activeDynamicClient{
		handler: func(method, rawURL string, headers map[string]string) httpclient.ResponseRecord {
			if strings.Contains(rawURL, "akca_jsonp_cb_") {
				parts := strings.Split(rawURL, "callback=")
				cb := "callback"
				if len(parts) > 1 {
					cb = strings.Split(parts[1], "&")[0]
				}
				return httpclient.ResponseRecord{
					StatusCode: 200,
					Body:       cb + `({"user_id":42,"email":"user@example.com","role":"admin"})`,
					Headers:    map[string]string{"Content-Type": "application/javascript"},
				}
			}
			return httpclient.ResponseRecord{StatusCode: 200, Body: `{"user_id":42}`}
		},
	}

	r := newActiveRunner(t, c)
	target := ScanTarget{EndpointURL: "https://example.com/api/user?callback=myFunc", Parameter: "callback", Method: "GET"}
	findings := r.runJSONPCallback(context.Background(), target)

	if len(findings) == 0 {
		t.Fatal("expected JSONP finding")
	}
	if findings[0].Severity != "high" {
		t.Fatalf("expected high severity due to sensitive user fields, got %s", findings[0].Severity)
	}
}

type activeDynamicClient struct {
	handler func(method, rawURL string, headers map[string]string) httpclient.ResponseRecord
}

func (c *activeDynamicClient) Do(_ context.Context, method, rawURL string, _ []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	resp := c.handler(method, rawURL, headers)
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Headers: headers},
		Response: resp,
	}, nil
}

func TestAPIVersioningRedirectAndHTMLRejection(t *testing.T) {
	c := &activeDynamicClient{
		handler: func(method, rawURL string, headers map[string]string) httpclient.ResponseRecord {
			switch {
			case strings.HasSuffix(rawURL, "/api/v1"):
				// Genuine API version returning JSON
				return httpclient.ResponseRecord{
					StatusCode: 200,
					Body:       `{"status":"ok","version":"1.0","routes":["/users","/items"]}`,
					Headers:    map[string]string{"Content-Type": "application/json"},
				}
			case strings.HasSuffix(rawURL, "/v1"):
				// Simulates 302 redirect to /login which returned 200 HTML
				return httpclient.ResponseRecord{
					StatusCode:    200,
					InitialStatus: 302,
					Redirected:    true,
					FinalURL:      "https://example.com/login",
					Body:          "<!DOCTYPE html><html><body>Login Page</body></html>",
					Headers:       map[string]string{"Content-Type": "text/html"},
				}
			case strings.HasSuffix(rawURL, "/v2"):
				// Direct 200 but HTML SPA landing / custom 404
				return httpclient.ResponseRecord{
					StatusCode: 200,
					Body:       "<html><head><title>App</title></head><body>SPA Root</body></html>",
					Headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
				}
			default:
				return httpclient.ResponseRecord{StatusCode: 404, Body: "not found"}
			}
		},
	}

	cfg := config.DefaultScanConfig()
	cfg.EnableInformationalChecks = true
	cfg.IncludeDomains = []string{"example.com"}
	r := NewRunner("scan-active-test", c, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil), nil, func(string, string, map[string]interface{}) error { return nil }, cfg)
	target := ScanTarget{EndpointURL: "https://example.com", Method: "GET"}
	findings := r.runAPIVersioning(context.Background(), target)

	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 API versioning finding (/api/v1), got %d: %+v", len(findings), findings)
	}
	if findings[0].Evidence.Payload.Value != "/api/v1" {
		t.Fatalf("expected finding for /api/v1, got %s", findings[0].Evidence.Payload.Value)
	}
}

