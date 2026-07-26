package urlutil

import "testing"

func TestIsPlausibleEndpointURL(t *testing.T) {
	ok := []string{
		"https://example.com/path?q=1",
		"http://localhost:8080/api",
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
	}
	for _, u := range bad {
		if IsPlausibleEndpointURL(u) {
			t.Fatalf("expected reject: %s", u)
		}
	}
}
