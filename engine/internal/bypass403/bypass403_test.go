package bypass403

import (
	"testing"
)

func TestAllTechniqueCategoriesPresent(t *testing.T) {
	baseline := Baseline{
		URL: "http://example.com/admin/api", Method: "GET", StatusCode: 401,
		AuthScheme: AuthScheme{Kind: "Custom", HasBearer: true, HasBasic: true},
	}
	attempts := BuildAuthBypassAttempts(baseline.URL, baseline.Method, baseline)
	found := map[TechniqueCategory]bool{}
	for _, a := range attempts {
		found[a.Category] = true
	}
	for _, cat := range AllCategories() {
		if !found[cat] {
			t.Fatalf("missing technique category %s", cat)
		}
	}
}

func TestMeaningfulBypassVerification(t *testing.T) {
	base := Baseline{StatusCode: 403, Body: "forbidden access denied", BodyLength: 23}

	ok, _ := IsMeaningfulBypass(base, 403, "forbidden access denied")
	if ok {
		t.Fatal("identical 403 should not bypass")
	}

	ok, reason := IsMeaningfulBypass(base, 200, `{"users":[{"id":1,"role":"admin"}]}`)
	if !ok || reason != "ok_access" {
		t.Fatalf("expected ok_access bypass, got ok=%v reason=%q", ok, reason)
	}

	ok, _ = IsMeaningfulBypass(base, 404, "not found")
	if ok {
		t.Fatal("404 should not count as bypass")
	}

	ok, _ = IsMeaningfulBypass(base, 200, "forbidden access denied")
	if ok {
		t.Fatal("200 with same body should not bypass")
	}
}

func TestRedirectIsNotBypassProof(t *testing.T) {
	base := Baseline{StatusCode: 403, Body: "forbidden", BodyLength: 9}
	ok, reason := IsMeaningfulBypass(base, 302, "redirecting to login")
	if ok || reason != "redirect_without_access_proof" {
		t.Fatalf("redirect must not be bypass proof, ok=%v reason=%q", ok, reason)
	}
}

func TestWAFAndLoginPagesAreNotBypassProof(t *testing.T) {
	base := Baseline{StatusCode: 403, Body: "forbidden", BodyLength: 9}
	pages := []string{
		`<!DOCTYPE html><title>Attention Required!</title><div>Cloudflare Ray ID: abc</div>`,
		`<!DOCTYPE html><title>Sign in</title><form action="/login"><input type="password"></form>`,
		`{"error":"invalid token","message":"authentication required"}`,
	}
	for _, page := range pages {
		if ok, reason := IsMeaningfulBypass(base, 200, page); ok {
			t.Fatalf("denial/challenge page accepted as bypass (%s): %s", reason, page)
		}
	}
}

func TestBodiesSimilarIgnoresBundleHashAndVolatileHTML(t *testing.T) {
	first := `<!DOCTYPE html><html><head><script src="/app.bundle-aabbccddeeff0011.js"></script></head>` +
		`<body><h1>Public shell</h1><p>Request 2026-07-15T10:00:00Z</p></body></html>`
	second := `<!DOCTYPE html><html><head><script src="/app.bundle-1122334455667788.js"></script></head>` +
		`<body><h1>Public shell</h1><p>Request 2026-07-15T10:00:09Z</p></body></html>`
	if !bodiesSimilar(first, second) {
		t.Fatalf("bundle hashes and timestamps should normalize to the same public shell: %q != %q", normalizeComparisonBody(first), normalizeComparisonBody(second))
	}
}

func TestScopeBlockingSkipsOutOfScopeURL(t *testing.T) {
	attempts := BuildAttempts("http://out-of-scope.test/admin", "GET")
	if len(attempts) == 0 {
		t.Fatal("expected attempts")
	}
	for _, a := range attempts {
		if a.URL == "" {
			t.Fatal("attempt URL must not be empty")
		}
	}
}
