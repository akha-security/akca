package modules

import (
	"context"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestUserRedirectNestedQueryIsNotDestination(t *testing.T) {
	for _, location := range []string{
		"https://l.facebook.com/l.php?u=https%3A%2F%2Fwww.facebook.com%2Fads%2Fcreate%2F%3Fextra_1%3Dhttps%253A%252F%252Fevil.example%252Fakca",
		"https://safe.example/?next=https://evil.example/akca",
		"https://evil.example@safe.example/", "https://evil.example.safe.example/", "/evil.example", "javascript:alert(1)",
	} {
		rr := httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: 302, Headers: map[string]string{"Location": location}}}
		if openRedirectSignal(rr, "https://evil.example/akca") || openRedirectHeaderConfirmed(rr.Response.Headers, "parameter_redirect") {
			t.Fatalf("false redirect for %q", location)
		}
	}
	for _, location := range []string{"https://evil.example/akca", "//evil.example/akca", "https://user@evil.example/"} {
		if !redirectDestinationIsCanary(location) {
			t.Fatalf("real redirect missed: %s", location)
		}
	}
}

func TestUserCORS400TrustedSubdomain(t *testing.T) {
	c := auditDoer(func(_ context.Context, m, u string, b []byte, h map[string]string) (httpclient.RequestResponse, error) {
		return httpclient.RequestResponse{Request: httpclient.RequestRecord{Method: m, URL: u, Headers: h}, Response: httpclient.ResponseRecord{StatusCode: 400, Headers: map[string]string{"Access-Control-Allow-Origin": h["Origin"], "Access-Control-Allow-Credentials": "true", "Access-Control-Allow-Methods": "OPTIONS"}, Body: "<html><title>Error</title><h1>Sorry, something went wrong.</h1></html>"}}, nil
	})
	r := newActiveRunner(t, c)
	if fs := r.runCORS(context.Background(), ScanTarget{EndpointURL: "https://example.com/api/graphql", Method: "POST"}); len(fs) != 0 {
		t.Fatal("error page was reported as CORS vulnerability")
	}
	if corsSignalConfirmed(nil, map[string]string{"Access-Control-Allow-Origin": "https://trusted-sub.www.facebook.com"}, "trusted_subdomain", "https://trusted-sub.www.facebook.com") {
		t.Fatal("unproven subdomain ownership accepted")
	}
}

func TestUserCSTIAlertTextAndPrototypeTextAreNotExecution(t *testing.T) {
	if cstiSignalConfirmed("escaped constructor with alert(1)", "normal", `{{constructor.constructor('alert(1)')()}}`, "csti_expression_evaluated", 200) {
		t.Fatal("alert text treated as execution")
	}
	c := auditDoer(func(_ context.Context, m, u string, b []byte, h map[string]string) (httpclient.RequestResponse, error) {
		text := "normal page"
		if strings.Contains(u, "__proto__") {
			text = "Object prototype documentation __proto__ reflected in watch parameter"
		}
		return httpclient.RequestResponse{Request: httpclient.RequestRecord{Method: m, URL: u, Headers: h}, Response: httpclient.ResponseRecord{StatusCode: 200, Body: text}}, nil
	})
	r := newActiveRunner(t, c)
	if fs := r.runPrototypePollution(context.Background(), ScanTarget{EndpointURL: "https://example.com/watch", Method: "GET", Parameter: "v", Location: "query"}); len(fs) != 0 {
		t.Fatal("prototype text produced client pollution finding")
	}
}

func TestUserPublicJSONSuffixIsNotAuthBypass(t *testing.T) {
	calls := 0
	c := auditDoer(func(_ context.Context, m, u string, b []byte, h map[string]string) (httpclient.RequestResponse, error) {
		calls++
		return httpclient.RequestResponse{Request: httpclient.RequestRecord{Method: m, URL: u}, Response: httpclient.ResponseRecord{StatusCode: 200, Body: "<html><body>Public ayran category products</body></html>"}}, nil
	})
	r := newActiveRunner(t, c)
	if fs := r.runRouteAuthBypass(context.Background(), ScanTarget{EndpointURL: "https://example.com/ayran-x-c105440", Method: "GET", Parameter: "User-Agent", Location: "header"}); len(fs) != 0 || calls != 1 {
		t.Fatalf("public route: findings=%d calls=%d", len(fs), calls)
	}
}

type cstiProofRenderer struct{ literal bool }

func (b cstiProofRenderer) Render(_ context.Context, u string) (string, error) {
	decoded, _ := url.QueryUnescape(u)
	marker := regexp.MustCompile(`akca-csti-[a-zA-Z0-9_-]+`).FindString(decoded)
	if marker == "" {
		return "<html><body>normal</body></html>", nil
	}
	if b.literal {
		return "<html><body>&lt;html data-akca-csti=&#34;" + marker + "&#34;&gt;</body></html>", nil
	}
	return `<html data-akca-csti="` + marker + `"><body>executed</body></html>`, nil
}
func TestCSTIBrowserProofAndEscapedMarker(t *testing.T) {
	for _, literal := range []bool{false, true} {
		c := auditDoer(func(_ context.Context, m, u string, b []byte, h map[string]string) (httpclient.RequestResponse, error) {
			return httpclient.RequestResponse{Request: httpclient.RequestRecord{Method: m, URL: u}, Response: httpclient.ResponseRecord{StatusCode: 200, Body: "<html><body>template page</body></html>"}}, nil
		})
		r := newActiveRunner(t, c)
		r.browser = cstiProofRenderer{literal: literal}
		fs := r.runCSTI(context.Background(), ScanTarget{EndpointURL: "https://example.com/profile", Method: "GET", Parameter: "name", Location: "query"})
		if (len(fs) > 0) == literal {
			t.Fatalf("literal=%v findings=%d", literal, len(fs))
		}
	}
}
