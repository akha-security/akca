package bypass403

import "testing"

func TestParseWWWAuthenticateBearer(t *testing.T) {
	s := ParseWWWAuthenticate(`Bearer realm="api", charset="UTF-8"`)
	if s.Kind != "Bearer" || !s.HasBearer {
		t.Fatalf("expected Bearer scheme, got %+v", s)
	}
}

func TestParseWWWAuthenticateBasic(t *testing.T) {
	s := ParseWWWAuthenticate(`Basic realm="Restricted"`)
	if s.Kind != "Basic" || !s.HasBasic {
		t.Fatalf("expected Basic scheme, got %+v", s)
	}
}

func TestBuildAuthBypassAttemptsIncludesJWT(t *testing.T) {
	baseline := Baseline{
		URL: "https://example.com/api/admin", Method: "GET", StatusCode: 401,
		AuthScheme: ParseWWWAuthenticate(`Bearer realm="api"`),
	}
	attempts := BuildAuthBypassAttempts(baseline.URL, baseline.Method, baseline)
	if len(attempts) < 50 {
		t.Fatalf("expected many attempts, got %d", len(attempts))
	}
	var jwtCount int
	for _, a := range attempts {
		if a.Category == JWTBearerAbuse {
			jwtCount++
		}
	}
	if jwtCount < 8 {
		t.Fatalf("expected JWT bearer probes, got %d", jwtCount)
	}
}

func TestBuildAuthBypassAttemptsHopByHop(t *testing.T) {
	baseline := Baseline{URL: "https://example.com/admin", Method: "GET", StatusCode: 403}
	attempts := BuildAuthBypassAttempts(baseline.URL, baseline.Method, baseline)
	found := false
	for _, a := range attempts {
		if a.Category == HopByHopStrip && a.Label == "connection_strip_authorization" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected hop-by-hop strip attempt")
	}
}

func TestIsMeaningful401Bypass200(t *testing.T) {
	base := Baseline{StatusCode: 401, Body: "Unauthorized", BodyLength: 12}
	ok, _ := IsMeaningfulBypass(base, 200, `{"admin":true}`)
	if !ok {
		t.Fatal("expected 401->200 bypass")
	}
}

func TestIsMeaningful401Downgrade(t *testing.T) {
	base := Baseline{StatusCode: 401, Body: "need auth token", BodyLength: 15}
	ok, reason := IsMeaningfulBypass(base, 403, "forbidden but different")
	if ok || reason != "still_forbidden" {
		t.Fatalf("401->403 must remain blocked, ok=%v reason=%q", ok, reason)
	}
}
