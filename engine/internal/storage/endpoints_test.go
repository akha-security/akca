package storage

import (
	"encoding/json"
	"testing"
)

func TestMergeDiscoveryTrailPrefersCapturedBrowserRequest(t *testing.T) {
	existing := `{"url":"https://example.test/login","method":"POST","source":"browser_xhr","request_template":{"method":"POST","url":"https://example.test/login","headers":{"Content-Type":"application/x-www-form-urlencoded","X-Requested-With":"XMLHttpRequest","Referer":"https://example.test/"},"body":"username=alice&password=secret","content_type":"application/x-www-form-urlencoded"}}`
	incoming := `{"url":"https://example.test/login","method":"POST","source":"form","request_template":{"method":"POST","url":"https://example.test/login","headers":{"content-type":"text/plain"},"body":"username=admin&password=Password123%21","content_type":"application/x-www-form-urlencoded"}}`
	merged := mergeDiscoveryTrail(existing, incoming)
	var doc struct {
		RequestTemplate struct {
			Body    string            `json:"body"`
			Headers map[string]string `json:"headers"`
		} `json:"request_template"`
	}
	if err := json.Unmarshal([]byte(merged), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.RequestTemplate.Body != "username=alice&password=secret" {
		t.Fatalf("browser request body was replaced: %q", doc.RequestTemplate.Body)
	}
	if doc.RequestTemplate.Headers["X-Requested-With"] != "XMLHttpRequest" || doc.RequestTemplate.Headers["Referer"] == "" {
		t.Fatalf("captured browser headers were lost: %#v", doc.RequestTemplate.Headers)
	}
	if doc.RequestTemplate.Headers["Content-Type"] != "application/x-www-form-urlencoded" || doc.RequestTemplate.Headers["content-type"] != "" {
		t.Fatalf("case-insensitive captured header precedence was lost: %#v", doc.RequestTemplate.Headers)
	}
}
