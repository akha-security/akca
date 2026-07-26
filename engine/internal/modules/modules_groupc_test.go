package modules

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/reflection"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/verification"
)

type groupCClient struct {
	responses map[string]string
	headers   map[string]map[string]string
	statuses  map[string]int
}

type cachePoisonClient struct {
	poisoned  bool
	poisonURL string
	marker    string
}

func (c *cachePoisonClient) Do(_ context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	responseBody := "clean page"
	responseHeaders := map[string]string{"Content-Type": "text/html"}
	if headers["X-Forwarded-Host"] == "akca-cache-probe.invalid" {
		c.poisoned = true
		c.poisonURL = rawURL
		c.marker = "akca-cache-probe.invalid"
		responseBody = "canonical host: akca-cache-probe.invalid"
	} else if marker := headers["X-Forwarded-Host"]; marker != "" {
		c.poisoned = true
		c.poisonURL = rawURL
		c.marker = marker
		responseBody = "canonical host: " + marker
	} else if c.poisoned && rawURL == c.poisonURL {
		responseBody = "canonical host: " + c.marker
		responseHeaders["X-Cache"] = "HIT"
	}
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Headers: headers, Body: string(body)},
		Response: httpclient.ResponseRecord{StatusCode: 200, Body: responseBody, Headers: responseHeaders},
	}, nil
}

func (c *cachePoisonClient) DoWithoutSession(ctx context.Context, method, rawURL string, body []byte,
	headers map[string]string) (httpclient.RequestResponse, error) {
	return c.Do(ctx, method, rawURL, body, headers)
}

type authenticatedGroupCClient struct{}

func (authenticatedGroupCClient) Do(_ context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	return authResponse(method, rawURL, body, headers, "admin dashboard account settings")
}

func (authenticatedGroupCClient) DoWithoutSession(_ context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	return authResponse(method, rawURL, body, headers, "admin dashboard account settings")
}

func authResponse(method, rawURL string, body []byte, headers map[string]string, responseBody string) (httpclient.RequestResponse, error) {
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Headers: headers, Body: string(body)},
		Response: httpclient.ResponseRecord{StatusCode: 200, Body: responseBody, Headers: map[string]string{"Content-Type": "text/html"}},
	}, nil
}

func (m *groupCClient) lookup(rawURL string, body []byte, headers map[string]string) (string, int, map[string]string) {
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
	if origin := headers["Origin"]; origin != "" {
		okey := "origin:" + origin
		resp := m.responses[okey]
		if resp == "" {
			resp = m.responses["__default__"]
		}
		return resp, m.status(okey), m.headers[okey]
	}
	if auth := headers["Authorization"]; auth != "" {
		if resp, ok := m.responses[auth]; ok {
			return resp, m.status(auth), m.headers[auth]
		}
	}
	if h, ok := headers["Host"]; ok && h != "" {
		hostKey := "::host:" + h
		if resp, ok := m.responses[hostKey]; ok {
			return resp, m.status(hostKey), m.headers[hostKey]
		}
	}
	for hk, hv := range headers {
		headerKey := "hdr:" + strings.ToLower(hk) + ":" + hv
		if resp, ok := m.responses[headerKey]; ok {
			return resp, m.status(headerKey), m.headers[headerKey]
		}
	}
	key := m.urlKey(rawURL)
	if resp, ok := m.responses[key]; ok {
		return resp, m.status(key), m.headers[key]
	}
	return m.responses["__default__"], m.status(key), nil
}

func (m *groupCClient) status(key string) int {
	if s, ok := m.statuses[key]; ok {
		return s
	}
	return 200
}

func (m *groupCClient) urlKey(rawURL string) string {
	u, _ := url.Parse(rawURL)
	q := u.Query()
	for _, k := range []string{"url", "q", "user", "role", "redirect_uri", "state", "scope"} {
		if vals, ok := q[k]; ok && len(vals) > 0 {
			if len(vals) > 1 {
				return vals[0] + "+" + vals[1]
			}
			return vals[0]
		}
	}
	if u.Path != "" {
		return u.Path
	}
	return ""
}

func (m *groupCClient) Do(_ context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
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

func groupCRunner(t *testing.T, c *groupCClient) *Runner {
	t.Helper()
	cfg := config.DefaultScanConfig()
	return NewRunner("scan-c", c, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil), nil, func(string, string, map[string]interface{}) error { return nil }, cfg)
}

func TestCORSMisconfiguration(t *testing.T) {
	c := &groupCClient{
		responses: map[string]string{
			"origin:https://benign.example": "ok",
			"origin:null":                   "cors-null-body",
			"origin:https://evil.example":   "cors-evil-body",
		},
		headers: map[string]map[string]string{
			"origin:null": {"Access-Control-Allow-Origin": "null"},
			"origin:https://evil.example": {
				"Access-Control-Allow-Origin":      "https://evil.example",
				"Access-Control-Allow-Credentials": "true",
			},
		},
	}
	target := ScanTarget{EndpointURL: "http://example.com/api/data", Method: "GET", Parameter: "q"}
	findings := groupCRunner(t, c).runCORS(context.Background(), target)
	if len(findings) == 0 {
		t.Fatal("expected cors finding")
	}
}

func TestJWTMisconfiguration(t *testing.T) {
	token := buildJWT("none", `{"alg":"none","typ":"JWT"}`, `{"sub":"admin","role":"admin"}`)
	c := &groupCClient{responses: map[string]string{
		"Bearer " + token: "welcome admin authenticated",
	}}
	target := ScanTarget{EndpointURL: "http://example.com/api/auth", Method: "GET", Parameter: "q"}
	findings := groupCRunner(t, c).runJWT(context.Background(), target)
	if len(findings) != 0 {
		t.Fatal("JWT lead must remain manual until an automatic proof contract exists")
	}
}

func TestJWTIdentityChangeUsesSuccessfulValidBaseline(t *testing.T) {
	if !jwtModuleConfirmed(
		`{"sub":"akca-admin","role":"akca-admin"}`,
		`{"sub":"akca-user","role":"user"}`,
		"identity_change_confirmed", 200, 200,
	) {
		t.Fatal("a successful valid-token identity baseline must support JWT identity-boundary proof")
	}
	if jwtModuleConfirmed(`{"sub":"akca-admin"}`, `{"error":"unauthorized"}`,
		"identity_change_confirmed", 200, 401) {
		t.Fatal("an unauthorized baseline must not prove JWT identity escalation")
	}
}

func TestOAuthMisconfiguration(t *testing.T) {
	c := &groupCClient{responses: map[string]string{
		"https://app.example/callback":  "denied",
		"https://evil.example/callback": "redirecting to evil.example token",
	}}
	target := ScanTarget{EndpointURL: "http://example.com/oauth/authorize", Method: "GET", Parameter: "redirect_uri"}
	findings := groupCRunner(t, c).runOAuth(context.Background(), target)
	if len(findings) != 0 {
		t.Fatal("OAuth lead must remain manual until an automatic proof contract exists")
	}
}

func TestCachePoisoningUnkeyedHeader(t *testing.T) {
	c := &cachePoisonClient{}
	target := ScanTarget{EndpointURL: "http://example.com/", Method: "GET", Parameter: "akca"}
	cfg := config.DefaultScanConfig()
	r := NewRunner("scan-c", c, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil), nil, func(string, string, map[string]interface{}) error { return nil }, cfg)
	findings := r.runCachePoisoning(context.Background(), target)
	if len(findings) == 0 {
		t.Fatal("expected cache poisoning finding")
	}
}

func TestCachePoisoningSuppressesOrdinaryCacheHit(t *testing.T) {
	c := &groupCClient{
		responses: map[string]string{"__default__": "ordinary cached page"},
		headers: map[string]map[string]string{
			"hdr:x-forwarded-host:akca-cache-probe.invalid": {"X-Cache": "HIT"},
		},
	}
	target := ScanTarget{EndpointURL: "http://example.com/", Method: "GET", Parameter: "akca"}
	findings := groupCRunner(t, c).runCachePoisoning(context.Background(), target)
	if len(findings) != 0 {
		t.Fatalf("expected ordinary cache hit to be suppressed, got %d", len(findings))
	}
}

func TestCacheDeceptionPathConfusion(t *testing.T) {
	c := &sessionlessGroupCClient{groupCClient: &groupCClient{responses: map[string]string{
		"/account":                 `{"email":"user@example.com","password":"hidden","profile":true}`,
		"/account/nonexistent.css": `{"email":"user@example.com","password":"hidden","profile":true}`,
	}, headers: map[string]map[string]string{
		"/account/nonexistent.css": {"Content-Type": "text/css", "X-Cache": "HIT"},
	}}}
	target := ScanTarget{EndpointURL: "http://example.com/account", Method: "GET", Parameter: "q"}
	cfg := config.DefaultScanConfig()
	cfg.CacheDeceptionProofPolicies = []config.CacheDeceptionProofPolicy{{
		ID: "private-profile", URLContains: "/account", PrivateCanary: "user@example.com",
	}}
	runner := NewRunner("scan-cache", c, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil),
		nil, func(string, string, map[string]interface{}) error { return nil }, cfg)
	findings := runner.runCacheDeception(context.Background(), target)
	if len(findings) == 0 {
		t.Fatal("expected cache deception finding")
	}
}

type sessionlessGroupCClient struct{ *groupCClient }

func (c *sessionlessGroupCClient) DoWithoutSession(ctx context.Context, method, rawURL string, body []byte,
	headers map[string]string) (httpclient.RequestResponse, error) {
	return c.Do(ctx, method, rawURL, body, headers)
}

func TestCacheDeceptionRequiresCacheEvidence(t *testing.T) {
	body := `{"email":"user@example.com","password":"hidden","profile":true}`
	c := &groupCClient{responses: map[string]string{
		"/account":                 body,
		"/account/nonexistent.css": body,
	}, headers: map[string]map[string]string{
		"/account/nonexistent.css": {"Content-Type": "text/css"},
	}}
	target := ScanTarget{EndpointURL: "http://example.com/account", Method: "GET", Parameter: "q"}
	findings := groupCRunner(t, c).runCacheDeception(context.Background(), target)
	if len(findings) != 0 {
		t.Fatalf("expected uncached CSS-looking response to be suppressed, got %d", len(findings))
	}
}

func TestBrokenAuthUsesAnonymousControl(t *testing.T) {
	c := authenticatedGroupCClient{}
	cfg := config.DefaultScanConfig()
	r := NewRunner("scan-c", c, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil), nil, func(string, string, map[string]interface{}) error { return nil }, cfg)
	target := ScanTarget{EndpointURL: "http://example.com/admin", Method: "GET", Parameter: "q"}
	findings := r.runBrokenAuth(context.Background(), target)
	if len(findings) != 1 {
		t.Fatalf("two stable anonymous replays of the authenticated resource must confirm broken auth, got %d", len(findings))
	}
}

func TestBrokenAuthSkipsClientWithoutAnonymousMode(t *testing.T) {
	c := &groupCClient{responses: map[string]string{"__default__": "admin dashboard account settings"}}
	target := ScanTarget{EndpointURL: "http://example.com/admin", Method: "GET", Parameter: "q"}
	findings := groupCRunner(t, c).runBrokenAuth(context.Background(), target)
	if len(findings) != 0 {
		t.Fatalf("expected unsupported anonymous comparison to be skipped, got %d", len(findings))
	}
}

func TestMassAssignment(t *testing.T) {
	c := &groupCClient{responses: map[string]string{
		`{"name":"akca"}`:                `{"name":"akca","role":"user"}`,
		`{"name":"akca","role":"admin"}`: `{"name":"akca","role":"admin","elevated":true}`,
	}}
	target := ScanTarget{
		EndpointURL: "http://example.com/api/user", Method: "POST", Parameter: "body",
		Profile: reflection.ReflectionProfile{ContentType: "application/json"},
	}
	findings := groupCRunner(t, c).runMassAssignment(context.Background(), target)
	if len(findings) != 0 {
		t.Fatal("mass-assignment lead must remain manual until state change is proven")
	}
}

func TestMassAssignmentRejectsReserializedPayloadEcho(t *testing.T) {
	payload := `{"name":"akca","role":"admin"}`
	echo := `{ "name": "akca", "role": "admin" }`
	if massAssignmentSignal(echo, `{"name":"akca","role":"user"}`, payload) {
		t.Fatal("re-serialized request JSON must not prove mass assignment")
	}
	nestedEcho := `{"received":{"name":"akca","role":"admin"}}`
	if massAssignmentSignal(nestedEcho, `{"name":"akca","role":"user"}`, payload) {
		t.Fatal("payload nested in an echo container must not prove mass assignment")
	}
}

func TestMassAssignmentPersistentStateSignal(t *testing.T) {
	if !moduleSignalConfirmed("mass_assignment",
		defaultPayload("mass_assignment", "role_escalation", `{"role":"admin"}`, "role_escalation"),
		"role_escalation",
		httpclient.ResponseRecord{StatusCode: 200, Body: `{"name":"alice","role":"user"}`},
		httpclient.ResponseRecord{StatusCode: 200, Body: `{"name":"alice","role":"admin"}`},
		false, "",
	) {
		t.Fatal("verified before/after privilege state must reach the state-mutation proof engine")
	}
}

func TestAPIExcessiveExposure(t *testing.T) {
	c := &groupCClient{responses: map[string]string{
		"": `{"user":"test","password":"s3cret","token":"abc"}`,
	}}
	target := ScanTarget{EndpointURL: "http://example.com/api/users", Method: "GET", Parameter: "q"}
	findings := groupCRunner(t, c).runAPIExposure(context.Background(), target)
	if len(findings) == 0 {
		t.Fatal("expected api exposure finding")
	}
}

func TestRateLimitWeakness(t *testing.T) {
	c := &groupCClient{responses: map[string]string{"__default__": "invalid login attempt"}}
	target := ScanTarget{EndpointURL: "http://example.com/login", Method: "GET", Parameter: "user"}
	findings := groupCRunner(t, c).runRateLimit(context.Background(), target)
	if len(findings) != 0 {
		t.Fatal("rate-limit lead must remain manual until calibrated timing proof exists")
	}
}

func TestRateLimitWeaknessSuppressesGenericOK(t *testing.T) {
	c := &groupCClient{responses: map[string]string{"__default__": "ok"}}
	target := ScanTarget{EndpointURL: "http://example.com/login", Method: "GET", Parameter: "user"}
	findings := groupCRunner(t, c).runRateLimit(context.Background(), target)
	if len(findings) != 0 {
		t.Fatalf("expected generic 200 responses to be suppressed, got %d", len(findings))
	}
}

func TestRateLimitWeaknessSuppresses429(t *testing.T) {
	c := &groupCClient{
		responses: map[string]string{"__default__": "too many attempts"},
		statuses:  map[string]int{"user": 429},
	}
	target := ScanTarget{EndpointURL: "http://example.com/login", Method: "GET", Parameter: "user"}
	findings := groupCRunner(t, c).runRateLimit(context.Background(), target)
	if len(findings) != 0 {
		t.Fatalf("expected existing rate limit to suppress finding, got %d", len(findings))
	}
}

func TestAccountEnumeration(t *testing.T) {
	c := &groupCClient{responses: map[string]string{
		"valid@example.com":             "welcome back",
		"invalid-not-found@example.com": "user not found",
	}}
	target := ScanTarget{EndpointURL: "http://example.com/login", Method: "GET", Parameter: "user"}
	findings := groupCRunner(t, c).runAccountEnum(context.Background(), target)
	if len(findings) != 0 {
		t.Fatal("account-enumeration lead must remain manual until calibrated timing proof exists")
	}
}

func TestParameterPollution(t *testing.T) {
	c := &groupCClient{responses: map[string]string{
		"user":       "role is user",
		"admin+user": "role is admin elevated",
	}}
	target := ScanTarget{EndpointURL: "http://example.com/api/profile", Method: "GET", Parameter: "role"}
	findings := groupCRunner(t, c).runHPP(context.Background(), target)
	if len(findings) != 0 {
		t.Fatal("HPP lead must remain manual until a server-side effect is proven")
	}
}

func TestParameterPollutionRejectsEchoedAdminValue(t *testing.T) {
	if hppSignal("received parameter role=admin", "received parameter role=user") {
		t.Fatal("an echoed HPP value must not prove privilege escalation")
	}
	if hppArraySignal("submitted array values: user, admin", "submitted array values: user") {
		t.Fatal("an echoed HPP array must not prove privilege escalation")
	}
}

func TestCSRFRequiresMissingTokenProofAndInvalidControl(t *testing.T) {
	c := &groupCClient{
		responses: map[string]string{
			`amount=10&csrf_token=valid`: "transfer accepted",
			`amount=10`:                  "transfer accepted",
			`amount=10&csrf_token=akca-invalid-csrf-token`: "invalid csrf token",
		},
		statuses: map[string]int{`amount=10&csrf_token=akca-invalid-csrf-token`: 403},
	}
	cfg := config.DefaultScanConfig()
	cfg.SessionCookies = map[string]string{"session": "test"}
	runner := NewRunner("scan-csrf", c, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil), nil,
		func(string, string, map[string]interface{}) error { return nil }, cfg)
	target := ScanTarget{
		EndpointURL: "http://example.com/transfer", Method: "POST", Parameter: "csrf_token", Location: "form",
		BodyTemplate: "amount=10&csrf_token=valid",
		Profile:      reflection.ReflectionProfile{ContentType: "application/x-www-form-urlencoded"},
	}
	findings := runner.runCSRF(context.Background(), target)
	if len(findings) != 1 {
		t.Fatalf("expected one confirmed CSRF finding, got %d", len(findings))
	}
}

func TestCSRFSkipsWithoutAuthenticatedOriginalRequest(t *testing.T) {
	c := &groupCClient{responses: map[string]string{"__default__": "accepted"}}
	target := ScanTarget{EndpointURL: "http://example.com/transfer", Method: "POST", BodyTemplate: "amount=10&csrf_token=valid"}
	if findings := groupCRunner(t, c).runCSRF(context.Background(), target); len(findings) != 0 {
		t.Fatalf("unauthenticated request must not be reported as CSRF, got %d", len(findings))
	}
}

func TestGroupCManifestsPresent(t *testing.T) {
	if len(GroupCRegistry) < 10 {
		t.Fatalf("expected 10 group C modules, got %d", len(GroupCRegistry))
	}
}
