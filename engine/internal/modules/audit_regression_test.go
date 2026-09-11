package modules

import (
	"context"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/learning"
	"github.com/akha-security/akca/engine/internal/verification"
	"net/url"
	"strings"
	"testing"
)

type auditDoer func(context.Context, string, string, []byte, map[string]string) (httpclient.RequestResponse, error)

func (f auditDoer) Do(c context.Context, m, u string, b []byte, h map[string]string) (httpclient.RequestResponse, error) {
	return f(c, m, u, b, h)
}

func TestRegressionPublicJSONPIsNotPrivateDisclosure(t *testing.T) {
	c := auditDoer(func(_ context.Context, m, raw string, b []byte, h map[string]string) (httpclient.RequestResponse, error) {
		u, _ := url.Parse(raw)
		cb := u.Query().Get("callback")
		body := `{"user_id":"public-author","display_name":"Public blog author"}`
		if cb != "" {
			body = cb + "(" + body + ");"
		}
		return httpclient.RequestResponse{Request: httpclient.RequestRecord{Method: m, URL: raw, Headers: h}, Response: httpclient.ResponseRecord{StatusCode: 200, Body: body, Headers: map[string]string{"Content-Type": "application/javascript"}}}, nil
	})
	fs := newActiveRunner(t, c).runJSONPCallback(context.Background(), ScanTarget{EndpointURL: "https://example.com/public-authors", Method: "GET", Parameter: "callback", Location: "query"})
	if len(fs) != 0 {
		t.Fatal("public JSONP must remain discovery, not a vulnerability")
	}
}

func TestRegressionLLMRefusalIsNotPromptLeak(t *testing.T) {
	c := &llmMockClient{responseHandler: func(m, u, b string) string {
		if strings.Contains(b, "Ignore previous instructions") {
			return `{"response":"I cannot disclose my system prompt: those instructions are private."}`
		}
		return `{"response":"Hello. How can I help?"}`
	}}
	fs := newActiveRunner(t, c).runLLMInjection(context.Background(), ScanTarget{EndpointURL: "https://example.com/api/chat", Method: "POST", Parameter: "message", Location: "json", BodyTemplate: `{"message":"hello"}`})
	if len(fs) != 0 {
		t.Fatal("refusal must not be a disclosure")
	}
}

func TestRegressionPublicWSHeaderIsNotAmbientAuthentication(t *testing.T) {
	c := auditDoer(func(_ context.Context, m, u string, b []byte, h map[string]string) (httpclient.RequestResponse, error) {
		status, body := 200, "Public realtime feed"
		if h["Upgrade"] == "websocket" {
			status = 101
			body = ""
		}
		return httpclient.RequestResponse{Request: httpclient.RequestRecord{Method: m, URL: u, Headers: h}, Response: httpclient.ResponseRecord{StatusCode: status, Body: body, Headers: map[string]string{"Content-Type": "text/plain"}}}, nil
	})
	r := newActiveRunner(t, c)
	r.cfg.CustomHeaders = map[string]string{"Accept-Language": "tr"}
	fs := r.runCrossSiteWebSocketHijack(context.Background(), ScanTarget{EndpointURL: "https://example.com/stream", Method: "GET"})
	if len(fs) != 0 {
		t.Fatal("public WS must not be a vulnerability")
	}
}

func TestRegressionSameSecondResponseIsNotCacheEvidence(t *testing.T) {
	h := map[string]string{"Date": "Wed, 09 Sep 2026 10:00:00 GMT"}
	if hasCacheHitEvidence(h, h, "normal response", "normal response") {
		t.Fatal("regression in verified behavior")
	}
}

func TestRegressionEqualLengthDifferentBodiesAreNotSimilar(t *testing.T) {
	if bodiesSimilar(strings.Repeat("A", 100), strings.Repeat("B", 100)) {
		t.Fatal("regression in verified behavior")
	}
}

func TestRegressionLearning(t *testing.T) {
	p := learning.NewProfile("example.com", "")
	for i := 0; i < 100; i++ {
		p = p.Record("sqli", learning.OutcomeFalsePositive)
	}
	if p.FalsePositiveRate("sqli") != 1 {
		t.Fatal("learning regression in verified behavior")
	}
}

func (f auditDoer) DoWithoutSession(c context.Context, m, u string, b []byte, h map[string]string) (httpclient.RequestResponse, error) {
	return f(c, m, u, b, h)
}

func TestRegressionPublicAlternateRouteIsNotAuthBypass(t *testing.T) {
	c := auditDoer(func(_ context.Context, m, raw string, b []byte, h map[string]string) (httpclient.RequestResponse, error) {
		u, _ := url.Parse(raw)
		status, body := 404, "Not Found"
		if u.Path == "/" {
			status = 200
			body = "Home"
		}
		if strings.Contains(u.Path, ";") {
			status = 200
			body = "This is a public documentation article. All visitors may read this content without signing in."
		}
		return httpclient.RequestResponse{Request: httpclient.RequestRecord{Method: m, URL: raw, Headers: h}, Response: httpclient.ResponseRecord{StatusCode: status, Body: body, Headers: map[string]string{"Content-Type": "text/plain"}}}, nil
	})
	fs := newActiveRunner(t, c).runRouteAuthBypass(context.Background(), ScanTarget{EndpointURL: "https://example.com/admin/article", Method: "GET"})
	if len(fs) != 0 {
		t.Fatal("public alternative route must not be a bypass")
	}
}

func TestRegressionOrdinaryJSONParsingIsNotBoundaryViolation(t *testing.T) {
	c := auditDoer(func(_ context.Context, m, u string, b []byte, h map[string]string) (httpclient.RequestResponse, error) {
		body := `{"result":"no input supplied"}`
		if len(b) > 0 {
			body = `{"result":"request received and parsed normally"}`
		}
		return httpclient.RequestResponse{Request: httpclient.RequestRecord{Method: m, URL: u, Body: string(b), Headers: h}, Response: httpclient.ResponseRecord{StatusCode: 200, Body: body, Headers: map[string]string{"Content-Type": "application/json"}}}, nil
	})
	fs := newActiveRunner(t, c).runParserDifferential(context.Background(), ScanTarget{EndpointURL: "https://example.com/parser", Method: "GET", BodyTemplate: `{"value":1}`})
	if len(fs) != 0 {
		t.Fatal("normal parser behavior must not be a vulnerability")
	}
}

func TestRegressionCORSReflectedOriginsAreDetected(t *testing.T) {
	c := auditDoer(func(_ context.Context, m, u string, b []byte, h map[string]string) (httpclient.RequestResponse, error) {
		rh := map[string]string{"Content-Type": "application/json"}
		if origin := h["Origin"]; strings.HasPrefix(origin, "https://") || strings.HasPrefix(origin, "http://") {
			rh["Access-Control-Allow-Origin"] = origin
			rh["Access-Control-Allow-Credentials"] = "true"
		}
		return httpclient.RequestResponse{Request: httpclient.RequestRecord{Method: m, URL: u, Body: string(b), Headers: h}, Response: httpclient.ResponseRecord{StatusCode: 200, Body: `{"private_data":"audit private user profile"}`, Headers: rh}}, nil
	})
	fs := newActiveRunner(t, c).runCORS(context.Background(), ScanTarget{EndpointURL: "https://example.com/api/profile", Method: "GET"})
	if len(fs) == 0 {
		t.Fatalf("arbitrary origin CORS was missed: got %d findings", len(fs))
	}
}

func TestRegressionSecondOrderBrowserExecutionIsDetected(t *testing.T) {
	marker := `<script>window.__akca_xss_confirmed=true</script>`
	c := auditDoer(func(_ context.Context, m, u string, b []byte, h map[string]string) (httpclient.RequestResponse, error) {
		return httpclient.RequestResponse{Request: httpclient.RequestRecord{Method: m, URL: u, Headers: h}, Response: httpclient.ResponseRecord{StatusCode: 200, Body: "<html>" + marker + "</html>", Headers: map[string]string{"Content-Type": "text/html"}}}, nil
	})
	r := newActiveRunner(t, c)
	r.cfg.EnableSecondOrderTracking = true
	r.stored["https://example.com/post::q"] = marker
	r.browser = executedDOMRenderer{}
	var last verification.Result
	r.verifier = verification.NewEngine(nil, func(_, _ string, p map[string]interface{}) error {
		if s, ok := p["suppressed"].(bool); ok {
			last.Suppressed = s
		}
		return nil
	})
	fs := r.runSecondOrder(context.Background(), ScanTarget{EndpointURL: "https://example.com/profile", Method: "GET", Parameter: "view", Location: "query"})
	if len(fs) == 0 || last.Suppressed {
		t.Fatalf("browser execution was suppressed: findings=%d suppressed=%v", len(fs), last.Suppressed)
	}
}

func TestRegressionReplayHashIncludesSecurityHeaders(t *testing.T) {
	obs := func(location string) verification.Observation {
		return verification.NewHTTPObservation("audit", "open_redirect", "https://example.com/redirect", "next", "query", verification.RolePositiveProbe, 1, "", "GET", "https://example.com/redirect?next=external", "", nil, verification.ResponseSnapshot{StatusCode: 302, Body: "", Headers: map[string]string{"Location": location}})
	}
	a, b := obs("https://attacker.example/"), obs("/safe")
	if a.NormalizedHash == b.NormalizedHash {
		t.Fatal("regression in verified behavior")
	}
}

func TestRegressionCoverageExcludesSkippedTargets(t *testing.T) {
	calls := 0
	c := auditDoer(func(_ context.Context, m, u string, b []byte, h map[string]string) (httpclient.RequestResponse, error) {
		calls++
		return httpclient.RequestResponse{}, nil
	})
	r := newActiveRunner(t, c)
	var finished map[string]interface{}
	r.emit = func(kind, _ string, p map[string]interface{}) error {
		if kind == "vuln_module_finished" {
			finished = p
		}
		return nil
	}
	_, err := r.RunModule(context.Background(), "parser_differential", []ScanTarget{{EndpointURL: "https://example.com/api/user", Method: "POST", BodyTemplate: `{"role":"user"}`}})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 || finished["coverage_percentage"] != "0.0%" {
		t.Fatalf("regression in verified behavior: network calls=%d event=%v", calls, finished)
	}
}

func TestRegressionSmugglingProofDoesNotUseOrdinaryReplay(t *testing.T) {
	calls := 0
	c := auditDoer(func(_ context.Context, m, u string, b []byte, h map[string]string) (httpclient.RequestResponse, error) {
		calls++
		return httpclient.RequestResponse{Request: httpclient.RequestRecord{Method: m, URL: u, Headers: h}, Response: httpclient.ResponseRecord{StatusCode: 200, Body: "ordinary HTTP response", Headers: map[string]string{"Content-Type": "text/plain"}}}, nil
	})
	r := newActiveRunner(t, c)
	target := ScanTarget{EndpointURL: "https://example.com/", Method: "GET"}
	base := httpclient.RequestResponse{Request: httpclient.RequestRecord{Method: "GET", URL: target.EndpointURL}, Response: httpclient.ResponseRecord{StatusCode: 200, Body: "ordinary HTTP response"}}
	// Same evidence shape produced after the two raw TCP confirmations in runHTTPSmuggling.
	probe := httpclient.RequestResponse{Request: httpclient.RequestRecord{Method: "POST", URL: target.EndpointURL, Headers: map[string]string{"Transfer-Encoding": "chunked"}}, Response: httpclient.ResponseRecord{StatusCode: 404, Body: "akca-smuggle-audit-canary"}}
	f := r.verifyAndBuild(context.Background(), "http_smuggling", target, defaultPayload("http_smuggling", "http_desync_cl_te", "audit-canary", "http_desync_cl_te"), base, probe, "http_desync_cl_te", false, false, "", "")
	if f != nil || calls != 0 {
		t.Fatalf("regression in verified behavior: finding=%v calls=%d", f, calls)
	}
}

func TestRegressionCORSDoesNotFlagSameOrigin(t *testing.T) {
	c := auditDoer(func(_ context.Context, m, u string, b []byte, h map[string]string) (httpclient.RequestResponse, error) {
		headers := map[string]string{"Content-Type": "application/json"}
		if h["Origin"] == "http://example.com" {
			headers["Access-Control-Allow-Origin"] = "http://example.com"
			headers["Access-Control-Allow-Credentials"] = "true"
		}
		return httpclient.RequestResponse{Request: httpclient.RequestRecord{Method: m, URL: u, Headers: h}, Response: httpclient.ResponseRecord{StatusCode: 200, Body: `{"ok":true}`, Headers: headers}}, nil
	})
	r := newActiveRunner(t, c)
	if fs := r.runCORS(context.Background(), ScanTarget{EndpointURL: "http://example.com/api", Method: "GET"}); len(fs) != 0 {
		t.Fatalf("same-origin policy reported: %d", len(fs))
	}
}
func TestRegressionUncachedHeaderIsNotCacheHit(t *testing.T) {
	for _, value := range []string{"uncached", "miss", "miss from cachedproxy"} {
		if hasCacheHitEvidence(map[string]string{"X-Cache": value}, nil, "", "") {
			t.Fatalf("false cache hit for %q", value)
		}
	}
	if !hasCacheHitEvidence(map[string]string{"X-Cache": "TCP_HIT from edge"}, nil, "", "") {
		t.Fatal("real cache hit missed")
	}
}
