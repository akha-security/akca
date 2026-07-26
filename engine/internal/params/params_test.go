package params

import (
	"testing"
)

func TestWordlistAtLeast500(t *testing.T) {
	if WordlistSize() < 500 {
		t.Fatalf("wordlist size=%d want >=500", WordlistSize())
	}
}

func TestPassiveExtractionSources(t *testing.T) {
	body := `<form><input type="hidden" name="csrf" value="1"><input id="email" name="email"></form>
{"user":"x","token":"y"}`
	headers := map[string]string{"X-API-Key": "abc", "Cookie": "sid=1"}
	eps := ExtractPassive("https://example.com/oauth/callback?code=1&state=2", "GET", "text/html", body, headers)
	if len(eps) < 5 {
		t.Fatalf("expected multiple passive params, got %d", len(eps))
	}
}

func TestExtractJSONKeysIncludesNestedPaths(t *testing.T) {
	keys := extractJSONKeys(`{"user":{"profile":{"email":"a@example.test"}},"items":[{"id":1}]}`)
	for _, want := range []string{"user", "user.profile", "user.profile.email", "items.0.id"} {
		if _, ok := keys[want]; !ok {
			t.Fatalf("missing nested JSON path %q: %#v", want, keys)
		}
	}
}

func TestDifferentialAnalysis(t *testing.T) {
	base := Fingerprint(200, "ok", 100, map[string]string{"Content-Type": "text/plain"})
	diffStatus := Fingerprint(500, "ok", 100, map[string]string{"Content-Type": "text/plain"})
	diffBody := Fingerprint(200, "error", 100, map[string]string{"Content-Type": "text/plain"})
	if !Differs(base, diffStatus) {
		t.Fatal("status diff should be detected")
	}
	if !Differs(base, diffBody) {
		t.Fatal("body diff should be detected")
	}
	if Differs(base, base) {
		t.Fatal("identical fingerprints should not differ")
	}
}

// TestFingerprintIgnoresVolatileHeaders guards the regression where the
// response fingerprint hashed every header (including the always-changing Date
// header) in random map order, so two identical responses looked "different".
// That flooded parameter discovery with false positives and starved the real
// parameters out of the limited analysis budget.
func TestFingerprintIgnoresVolatileHeaders(t *testing.T) {
	a := Fingerprint(200, "same body", 100, map[string]string{
		"Content-Type": "text/html", "Date": "Mon, 01 Jan 2024 00:00:00 GMT",
		"Set-Cookie": "sid=aaa", "CF-RAY": "111", "Server": "nginx",
	})
	b := Fingerprint(200, "same body", 9999, map[string]string{
		"Server": "nginx", "Content-Type": "text/html",
		"Date": "Tue, 02 Jan 2024 11:22:33 GMT", "Set-Cookie": "sid=bbb", "CF-RAY": "222",
	})
	if Differs(a, b) {
		t.Fatal("responses differing only in volatile headers/timing must not be treated as different")
	}
}

func TestDiffersDetectsRealHeaderChange(t *testing.T) {
	base := Fingerprint(200, "body", 100, map[string]string{"Content-Type": "text/html"})
	changed := Fingerprint(200, "body", 100, map[string]string{"Content-Type": "application/json"})
	if !Differs(base, changed) {
		t.Fatal("a meaningful (non-volatile) header change should be detected")
	}
}

func TestExtractPassivePrioritizesRealQueryParams(t *testing.T) {
	eps := ExtractPassive("https://example.com/search?q=test", "GET", "text/html",
		"<html><body>Results for: test</body></html>", nil)
	var q *DiscoveredParameter
	for i := range eps {
		if eps[i].Name == "q" && eps[i].Location == LocationQuery {
			q = &eps[i]
		}
	}
	if q == nil {
		t.Fatal("real query parameter q not extracted")
	}
	if q.Priority < 95 {
		t.Fatalf("real query param should outrank speculative guesses, got priority %d", q.Priority)
	}
}

func TestExtractPassiveDoesNotParseHTMLAsXML(t *testing.T) {
	eps := ExtractPassive("https://example.com/", "GET", "text/html",
		"<html><body><h1>hi</h1></body></html>", nil)
	for _, e := range eps {
		if e.Location == LocationXML {
			t.Fatalf("HTML must not yield XML params, got %q", e.Name)
		}
	}
}

func TestMethodDependentPriority(t *testing.T) {
	p := DiscoveredParameter{
		Name: "debug", Location: LocationQuery, MethodDependent: true,
		AcceptedMethods: []string{"GET", "POST"}, Priority: 95,
	}
	if !p.MethodDependent || p.Priority < 90 {
		t.Fatalf("method-dependent param should be high priority: %+v", p)
	}
}
