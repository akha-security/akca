package config

import "testing"

func TestNormalizeProxyURLAcceptsHostPortShorthand(t *testing.T) {
	got, err := NormalizeProxyURL("127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	if got != "http://127.0.0.1:8080" {
		t.Fatalf("unexpected normalized proxy: %q", got)
	}
}

func TestNormalizeProxyURLRejectsUnsupportedOrAmbiguousValues(t *testing.T) {
	for _, raw := range []string{"ftp://127.0.0.1:21", "http:///missing-host", "http://127.0.0.1:8080/path"} {
		if _, err := NormalizeProxyURL(raw); err == nil {
			t.Fatalf("expected invalid proxy URL to be rejected: %q", raw)
		}
	}
}

func TestSafeProxyURLRemovesCredentials(t *testing.T) {
	got := SafeProxyURL("http://user:secret@127.0.0.1:8080")
	if got != "http://127.0.0.1:8080" {
		t.Fatalf("proxy credentials leaked or address changed: %q", got)
	}
}
