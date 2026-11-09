package targeting

import "testing"

func TestResourceClassificationPreservesDynamicAndPassiveCoverage(t *testing.T) {
	for _, tc := range []struct {
		resource Resource
		inactive bool
	}{
		{Resource{URL: "https://example.test/assets", Status: 200, ContentType: "text/html", Body: "Index of /assets"}, true},
		{Resource{URL: "https://example.test/app.js.map", ContentType: "application/json"}, true},
		{Resource{URL: "https://example.test/icon.svg", ContentType: "image/svg+xml"}, true},
		{Resource{URL: "https://example.test/assets/login", ContentType: "text/html", Body: `<form action="/login">`}, false},
		{Resource{URL: "https://example.test/assets/api", ContentType: "application/json"}, false},
		{Resource{URL: "https://example.test/handler.js", DynamicInput: true}, false},
		{Resource{URL: "https://example.test/assets", ForceActive: true}, false},
		{Resource{URL: "https://example.test/assets", Status: 404, ForceActive: true}, true},
		{Resource{URL: "https://example.test/search", Status: 403, Body: "checking your browser"}, true},
		{Resource{URL: "https://example.test/api/preview?url=https://origin.test"}, false},
	} {
		if got := InactiveReason(tc.resource) != ""; got != tc.inactive {
			t.Errorf("%+v inactive=%v, want=%v", tc.resource, got, tc.inactive)
		}
	}
	for _, raw := range []string{"https://example.test/assets", "https://example.test/assets/a.js", "https://example.test/static/123"} {
		if BypassCandidate(raw) {
			t.Errorf("asset entered bypass queue: %s", raw)
		}
	}
	if !BypassCandidate("https://example.test/custom-protected-handler") {
		t.Fatal("unknown protected application routes must remain eligible")
	}
}
