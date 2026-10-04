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
		"https://evil.example@safe.example/", "https://evil.example.safe.example/", "/evil.example",
	} {
		rr := httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: 302, Headers: map[string]string{"Location": location}}}
		if openRedirectSignal(rr, "https://evil.example/akca") || openRedirectHeaderConfirmed(rr.Response.Headers, "parameter_redirect") {
			t.Fatalf("false redirect for %q", location)
		}
	}
	for _, location := range []string{"https://evil.example/akca", "//evil.example/akca", "https://user@evil.example/", "javascript:alert(1)", "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="} {
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

type prototypeProofRenderer struct{}

func (prototypeProofRenderer) Render(context.Context, string) (string, error) {
	return "<html></html>", nil
}

func (prototypeProofRenderer) EvaluatePage(_ context.Context, rawURL, _ string) (string, error) {
	if strings.Contains(rawURL, "__proto__") {
		return `{"polluted":"akca_dom_polluted","src":null,"innerHTML":null,"url":null}`, nil
	}
	return `{"polluted":null,"src":null,"innerHTML":null,"url":null}`, nil
}

func TestClientPrototypePollutionRequiresBrowserRuntimeEvidence(t *testing.T) {
	c := auditDoer(func(_ context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
		return httpclient.RequestResponse{
			Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Body: string(body), Headers: headers},
			Response: httpclient.ResponseRecord{StatusCode: 200, Body: "normal", Headers: map[string]string{"Content-Type": "text/html"}},
		}, nil
	})
	runner := newActiveRunner(t, c)
	runner.browser = prototypeProofRenderer{}
	findings := runner.runPrototypePollution(context.Background(), ScanTarget{
		EndpointURL: "https://example.com/watch?v=1", Method: "GET", Parameter: "v", Location: "query",
	})
	if len(findings) != 1 || findings[0].Evidence.Signal != "client_prototype_pollution" {
		t.Fatalf("expected one browser-proven client prototype pollution finding, got %+v", findings)
	}
}

type countingPrototypeRenderer struct{ evaluations int }

func (b *countingPrototypeRenderer) Render(context.Context, string) (string, error) {
	return "<html></html>", nil
}

func (b *countingPrototypeRenderer) EvaluatePage(_ context.Context, rawURL, _ string) (string, error) {
	b.evaluations++
	if strings.Contains(rawURL, "__proto__") {
		return `{"polluted":"akca_dom_polluted","src":null,"innerHTML":null,"url":null}`, nil
	}
	return `{"polluted":null,"src":null,"innerHTML":null,"url":null}`, nil
}

func TestClientPrototypePollutionRunsOncePerQueryShape(t *testing.T) {
	calls := 0
	c := auditDoer(func(_ context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
		calls++
		return httpclient.RequestResponse{
			Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Body: string(body), Headers: headers},
			Response: httpclient.ResponseRecord{StatusCode: 200, Body: "<html>normal</html>", Headers: map[string]string{"Content-Type": "text/html"}},
		}, nil
	})
	runner := newActiveRunner(t, c)
	browser := &countingPrototypeRenderer{}
	runner.browser = browser
	first := ScanTarget{EndpointURL: "https://example.com/watch?a=1&b=2", Method: "GET", Parameter: "a", Location: "query"}
	second := ScanTarget{EndpointURL: "https://example.com/watch?a=7&b=9", Method: "GET", Parameter: "b", Location: "query"}
	if findings := runner.runPrototypePollution(context.Background(), first); len(findings) != 1 {
		t.Fatalf("first query shape should be browser-tested, got %+v", findings)
	}
	evaluations, requests := browser.evaluations, calls
	if findings := runner.runPrototypePollution(context.Background(), second); len(findings) != 0 {
		t.Fatalf("equivalent query shape produced duplicate findings: %+v", findings)
	}
	if browser.evaluations != evaluations || calls != requests {
		t.Fatalf("equivalent query shape repeated work: browser %d->%d, HTTP %d->%d", evaluations, browser.evaluations, requests, calls)
	}
}

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
