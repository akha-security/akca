package urlutil

import "testing"

func TestHasPathTemplate(t *testing.T) {
	for _, raw := range []string{"https://example.test/users/{id}", "https://example.test/users/%7Bid%7D", "https://example.test/users/:id", "https://example.test/users/[slug]"} {
		if !HasPathTemplate(raw) {
			t.Errorf("unresolved JS route was considered concrete: %s", raw)
		}
	}
	if HasPathTemplate("https://example.test/users/123") {
		t.Fatal("concrete resource was treated as a template")
	}
}

func TestIsPlausibleEndpointURL(t *testing.T) {
	ok := []string{
		"https://example.com/path?q=1",
		"http://localhost:8080/api",
		"http://testparker/artists.php?artist=1",
		"http://burpbountylab:8080/sqli/search?q=laptop",
		"http://dvwa/vulnerabilities/sqli/",
		"https://example.com/admin;version=2/users",
		"https://example.com/odata/Products(1)",
		"https://example.com/scripts/module.exports.js",
		"https://example.com/search?q=a%26%26b",
	}
	for _, u := range ok {
		if !IsPlausibleEndpointURL(u) {
			t.Fatalf("expected ok: %s", u)
		}
	}
	bad := []string{
		"",
		"javascript:alert(1)",
		"https://example.com/http://evil.com",
		"https://example.com/xss?name=%22+http%3A%2F%2Fsqli-name.%2F",
		"https://{{host}}/api",
		"https://example.com/:id/foo",
		"https://example.com/undefined",
		"https://example.com/null/foo",
		"https://example.com/api/v1/DD/MM/YYYY",
		"https://example.com/node_modules/pkg/index.js",
		"https://example.com/dashboard/%26%26%28j=E,E=null%29,E%26%26I.send%28E%29",
		"https://example.com/dashboard/code%3Dfunction%28%29%7Breturn%20data%7D",
		"https://example.com/dashboard/stream%3D%28x%29%3D%3Ex.value",
	}
	for _, u := range bad {
		if IsPlausibleEndpointURL(u) {
			t.Fatalf("expected reject: %s", u)
		}
	}
}
