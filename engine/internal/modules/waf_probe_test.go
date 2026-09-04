package modules

import (
	"context"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/models"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/verification"
)

type wafHeaderCaptureClient struct {
	headers []map[string]string
}

func (c *wafHeaderCaptureClient) Do(_ context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	copied := map[string]string{}
	for key, value := range headers {
		copied[key] = value
	}
	c.headers = append(c.headers, copied)
	return httpclient.RequestResponse{
		Request: httpclient.RequestRecord{Method: method, URL: rawURL, Body: string(body), Headers: headers},
		Response: httpclient.ResponseRecord{
			StatusCode: 200,
			Body:       "ok",
			Headers:    map[string]string{"Content-Type": "text/html"},
		},
	}, nil
}

func TestWAFHeadersAreLimitedToHighAndCriticalModules(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/waf.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Conn().Exec(`INSERT INTO scans(id,status,config_json) VALUES ('scan-waf','running','{}')`); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveWAFProfile("scan-waf", models.WAFProfile{
		Host: "example.com", Vendor: "Akamai", Confidence: 0.95,
	}); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultScanConfig()
	cfg.EnableWAFBypassHeaders = true
	client := &wafHeaderCaptureClient{}
	r := NewRunner("scan-waf", client, scope.NewEngine(cfg), db, verification.NewEngine(db, nil), nil, nil, cfg)
	target := ScanTarget{EndpointURL: "http://example.com/search", Method: "GET", Parameter: "q", Location: "query"}

	if _, err := r.probeForModule(context.Background(), "sqli", target, "' OR 1=1--"); err != nil {
		t.Fatal(err)
	}
	if got := client.headers[len(client.headers)-1]["X-Akca-Line-Fold"]; got != "1" {
		t.Fatalf("SQLi should receive WAF evasion header, got %q in %+v", got, client.headers[len(client.headers)-1])
	}

	if _, err := r.probeForModule(context.Background(), "open_redirect", target, "https://evil.example"); err != nil {
		t.Fatal(err)
	}
	if got := client.headers[len(client.headers)-1]["X-Akca-Line-Fold"]; got != "" {
		t.Fatalf("open_redirect is medium and must not receive WAF evasion header, got %q", got)
	}
	if got := r.ProbeCount(); got != 2 {
		t.Fatalf("payload probe count = %d, want 2", got)
	}
}

func TestModuleAllowsHeaderPayloadsUsesBaseSeverity(t *testing.T) {
	if !moduleAllowsHeaderPayloads("xss") || !moduleAllowsHeaderPayloads("ssrf") || !moduleAllowsHeaderPayloads("xxe") {
		t.Fatal("high and critical modules should allow header payloads")
	}
	if moduleAllowsHeaderPayloads("open_redirect") || moduleAllowsHeaderPayloads("crlf") ||
		moduleAllowsHeaderPayloads("api_versioning") || moduleAllowsHeaderPayloads("rate_limit") ||
		moduleAllowsHeaderPayloads("") {
		t.Fatal("medium/low/info/unknown modules should not allow header payloads")
	}
}

func TestLowInfoModulesDoNotInjectDiscoveredHeaderPayloads(t *testing.T) {
	client := &wafHeaderCaptureClient{}
	cfg := config.DefaultScanConfig()
	r := NewRunner("scan-low", client, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil), nil, nil, cfg)
	target := ScanTarget{EndpointURL: "http://example.com/api", Method: "GET", Parameter: "X-Test", Location: "header"}

	if _, err := r.probeForModule(context.Background(), "api_versioning", target, "v2"); err != nil {
		t.Fatal(err)
	}
	if got := client.headers[len(client.headers)-1]["X-Test"]; got != "" {
		t.Fatalf("info module must not inject discovered header payload, got %q", got)
	}

	if _, err := r.probeForModule(context.Background(), "sqli", target, "' OR 1=1--"); err != nil {
		t.Fatal(err)
	}
	if got := client.headers[len(client.headers)-1]["X-Test"]; got == "" {
		t.Fatal("critical module should still inject discovered header payload")
	}
}

func TestLowInfoModulesDoNotSendExplicitHeaderPayloads(t *testing.T) {
	client := &wafHeaderCaptureClient{}
	cfg := config.DefaultScanConfig()
	r := NewRunner("scan-low", client, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil), nil, nil, cfg)
	target := ScanTarget{EndpointURL: "http://example.com/login", Method: "POST", Parameter: "email", Location: "form"}

	if _, err := r.probeWithHeadersForModule(context.Background(), "rate_limit", target, "alice@example.com", map[string]string{
		"X-Forwarded-For": "198.51.100.20",
	}); err != nil {
		t.Fatal(err)
	}
	if got := client.headers[len(client.headers)-1]["X-Forwarded-For"]; got != "" {
		t.Fatalf("low module must not send explicit header payload, got %q", got)
	}
}
