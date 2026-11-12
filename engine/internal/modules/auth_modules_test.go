package modules

import (
	"context"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/verification"
)

// improperAuthClient distinguishes requests only by which headers were sent,
// modeling a backend that grants access based on a spoofable auth header
// rather than by URL.
type improperAuthClient struct {
	headerKey    string
	headerVal    string
	protectedURL string
	grantedBody  string
	deniedBody   string
}

func (c *improperAuthClient) Do(_ context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	granted := c.headerKey != "" && headers[c.headerKey] == c.headerVal
	respBody := c.deniedBody
	status := 401
	if granted {
		respBody = c.grantedBody
		status = 200
	}
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Headers: headers},
		Response: httpclient.ResponseRecord{StatusCode: status, Body: respBody, Headers: map[string]string{"Content-Type": "application/json"}},
	}, nil
}

func (c *improperAuthClient) DoWithoutSession(ctx context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	return c.Do(ctx, method, rawURL, body, headers)
}

func newImproperAuthRunner(t *testing.T, client HTTPDoer) *Runner {
	t.Helper()
	cfg := config.DefaultScanConfig()
	return NewRunner("scan-improper-auth", client, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil), nil,
		func(string, string, map[string]interface{}) error { return nil }, cfg)
}

func TestImproperAuthenticationUnauthenticatedSensitiveEndpoint(t *testing.T) {
	c := &activeTestClient{
		responses: map[string]httpclient.ResponseRecord{
			"GET https://example.com/api/admin": {
				StatusCode: 200, Body: `{"users":[{"id":1,"email":"a@example.com"}],"admin":true}`,
				Headers: map[string]string{"Content-Type": "application/json"},
			},
		},
	}
	r := newActiveRunner(t, c)
	target := ScanTarget{EndpointURL: "https://example.com/api/admin", Method: "GET"}
	findings := r.runImproperAuthentication(context.Background(), target)

	if len(findings) != 1 {
		t.Fatalf("expected one improper authentication finding, got %d", len(findings))
	}
	if findings[0].Severity != "high" {
		t.Fatalf("expected high severity, got %s", findings[0].Severity)
	}
	if findings[0].VulnClass != "improper_auth" {
		t.Fatalf("unexpected vuln class: %s", findings[0].VulnClass)
	}
}

func TestImproperAuthenticationSafeNegativeWhenEndpointRequiresAuth(t *testing.T) {
	c := &activeTestClient{
		responses: map[string]httpclient.ResponseRecord{
			"GET https://example.com/api/admin": {
				StatusCode: 401, Body: `{"error":"unauthorized"}`,
				Headers: map[string]string{"Content-Type": "application/json"},
			},
		},
	}
	r := newActiveRunner(t, c)
	target := ScanTarget{EndpointURL: "https://example.com/api/admin", Method: "GET"}
	findings := r.runImproperAuthentication(context.Background(), target)

	if len(findings) != 0 {
		t.Fatalf("expected no finding for a properly protected endpoint, got %d", len(findings))
	}
}

func TestImproperAuthenticationDefaultCredentialBypass(t *testing.T) {
	c := &improperAuthClient{
		headerKey: "Authorization", headerVal: "Basic YWRtaW46YWRtaW4=",
		grantedBody: `{"status":"success","user":"admin"}`,
		deniedBody:  `{"error":"unauthorized"}`,
	}
	r := newImproperAuthRunner(t, c)
	target := ScanTarget{EndpointURL: "https://example.com/api/dashboard", Method: "GET"}
	findings := r.runImproperAuthentication(context.Background(), target)

	if len(findings) != 1 {
		t.Fatalf("expected one default-credential bypass finding, got %d", len(findings))
	}
	if findings[0].Severity != "critical" {
		t.Fatalf("expected critical severity, got %s", findings[0].Severity)
	}
}

func TestImproperAuthenticationSafeNegativeWhenBypassHeadersRejected(t *testing.T) {
	c := &improperAuthClient{
		headerKey:   "", // no header ever grants access
		grantedBody: `{"status":"success"}`,
		deniedBody:  `{"error":"unauthorized"}`,
	}
	r := newImproperAuthRunner(t, c)
	target := ScanTarget{EndpointURL: "https://example.com/api/dashboard", Method: "GET"}
	findings := r.runImproperAuthentication(context.Background(), target)

	if len(findings) != 0 {
		t.Fatalf("expected no finding when bypass headers are rejected, got %d", len(findings))
	}
}
