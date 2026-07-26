package nosql

import "testing"

func TestAnalyzeMongoError(t *testing.T) {
	p := Probes("user")[0]
	ok, sig := Analyze("ok", "MongoError: unknown operator $where", p)
	if !ok || sig != "nosql_error_disclosure" {
		t.Fatalf("got ok=%v sig=%q", ok, sig)
	}
}

func TestAnalyzeMongoErrorNoGenericSyntax(t *testing.T) {
	p := Probes("user")[0]
	ok, _ := Analyze("syntax error in request", "syntax error in request body", p)
	if ok {
		t.Fatal("expected no signal for generic syntax error")
	}
}

func TestAnalyzeAuthBypass(t *testing.T) {
	p := Probe{Signal: "auth_bypass"}
	ctx := ResponseContext{
		BaselineBody:   `{"error":"invalid credentials"}`,
		ProbeBody:      `{"access_token":"eyJhbGciOiJIUzI1NiJ9.abc","token_type":"bearer"}`,
		ControlBody:    `{"error":"invalid credentials"}`,
		BaselineStatus: 401,
		ProbeStatus:    200,
		ControlStatus:  401,
	}
	ok, sig := AnalyzeWithContext(ctx, p)
	if !ok || sig != "nosql_auth_bypass" {
		t.Fatalf("got ok=%v sig=%q", ok, sig)
	}
}

func TestAnalyzeAuthBypassFalsePositiveWelcome(t *testing.T) {
	p := Probe{Signal: "auth_bypass"}
	ctx := ResponseContext{
		BaselineBody:   "welcome to our site — please login",
		ProbeBody:      "welcome to our dashboard profile section",
		BaselineStatus: 200,
		ProbeStatus:    200,
	}
	ok, _ := AnalyzeWithContext(ctx, p)
	if ok {
		t.Fatal("expected no auth bypass on generic welcome/profile text")
	}
}

func TestAnalyzeAuthBypassRequiresControlDifferential(t *testing.T) {
	p := Probe{Signal: "auth_bypass"}
	ctx := ResponseContext{
		BaselineBody:   `{"error":"invalid credentials"}`,
		ProbeBody:      `{"access_token":"abc","token_type":"bearer"}`,
		ControlBody:    `{"access_token":"abc","token_type":"bearer"}`,
		BaselineStatus: 401,
		ProbeStatus:    200,
		ControlStatus:  200,
	}
	ok, _ := AnalyzeWithContext(ctx, p)
	if ok {
		t.Fatal("expected no signal when control request also succeeds")
	}
}

func TestAnalyzeNoDataLeakOnLargeJSON(t *testing.T) {
	p := Probe{Signal: "operator_injection"}
	baseline := `{"items":[]}`
	probe := `{"items":[{"id":1},{"id":2},{"id":3},{"id":4}]}`
	ok, _ := Analyze(baseline, probe, p)
	if ok {
		t.Fatal("operator probes should not report on body size alone")
	}
}

func TestProbesForTargetSkipsAuthOnSearchAPI(t *testing.T) {
	probes := ProbesForTarget("q", "http://example.com/api/search", "application/json", "POST")
	for _, p := range probes {
		if p.Signal == "auth_bypass" {
			t.Fatal("auth bypass probes should not run on non-login API")
		}
	}
}

func TestGETAPIMissingContentTypeStillGetsBracketProbes(t *testing.T) {
	probes := ProbesForTarget("filter", "http://example.com/api/search", "", "GET")
	var bracket bool
	for _, probe := range probes {
		if probe.Mode == "bracket_query" {
			bracket = true
		}
		if probe.Signal == "auth_bypass" {
			t.Fatal("non-login GET API must not receive auth-bypass bodies")
		}
	}
	if !bracket {
		t.Fatal("GET API without a content type should retain bracket-operator coverage")
	}
}

func TestProbesForTargetIncludesAuthOnLogin(t *testing.T) {
	probes := ProbesForTarget("username", "http://example.com/api/login", "application/json", "POST")
	found := false
	for _, p := range probes {
		if p.Signal == "auth_bypass" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected auth bypass probes on login endpoint")
	}
}

func TestBracketProbeURL(t *testing.T) {
	raw, err := BracketProbeURL("http://example.com/login", "username", "ne")
	if err != nil {
		t.Fatal(err)
	}
	if raw == "" || !contains(raw, "%24ne") && !contains(raw, "[$ne]") {
		t.Fatalf("unexpected url %q", raw)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestProbesCount(t *testing.T) {
	if len(Probes("email")) < 8 {
		t.Fatalf("expected many nosql probes, got %d", len(Probes("email")))
	}
}
