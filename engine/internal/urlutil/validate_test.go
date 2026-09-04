package urlutil

import "testing"

func TestIsPlausibleEndpointURL(t *testing.T) {
	ok := []string{
		"https://example.com/path?q=1",
		"http://localhost:8080/api",
		"http://testparker/artists.php?artist=1",
		"http://burpbountylab:8080/sqli/search?q=laptop",
		"http://dvwa/vulnerabilities/sqli/",
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
	}
	for _, u := range bad {
		if IsPlausibleEndpointURL(u) {
			t.Fatalf("expected reject: %s", u)
		}
	}
}
