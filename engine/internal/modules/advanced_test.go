package modules

import (
	"context"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

// deserializationTestClient responds with a deserialization error/marker only
// when the request URL contains the configured marker substring, and a
// normal page otherwise. This lets a single client simulate the original
// probe, the generic negative control, and the generic stability replays
// that enrichVerification issues for this module.
type deserializationTestClient struct {
	marker string
}

func (c *deserializationTestClient) Do(_ context.Context, method, rawURL string, _ []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	body := "<html>normal page</html>"
	if strings.Contains(rawURL, c.marker) {
		body = "PHP Fatal error:  unserialize(): Error at offset 5 of 20 bytes"
	}
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Headers: headers},
		Response: httpclient.ResponseRecord{StatusCode: 200, Body: body, Headers: map[string]string{"Content-Type": "text/html"}},
	}, nil
}

func TestInsecureDeserializationErrorDisclosure(t *testing.T) {
	c := &deserializationTestClient{marker: "stdClass"}
	r := testRunner(t, c)
	target := ScanTarget{EndpointURL: "https://example.com/api/data?q=hello", Method: "GET", Parameter: "q", Location: "query"}
	findings := r.runInsecureDeserialization(context.Background(), target)

	if len(findings) != 1 {
		t.Fatalf("expected one insecure deserialization finding, got %d", len(findings))
	}
	if findings[0].VulnClass != "insecure_deserialization" {
		t.Fatalf("unexpected vuln class: %s", findings[0].VulnClass)
	}
}

func TestInsecureDeserializationSafeNegativeWhenNoErrorSurfaces(t *testing.T) {
	c := &deserializationTestClient{marker: "akca-no-such-marker"}
	r := testRunner(t, c)
	target := ScanTarget{EndpointURL: "https://example.com/api/data?q=hello", Method: "GET", Parameter: "q", Location: "query"}
	findings := r.runInsecureDeserialization(context.Background(), target)

	if len(findings) != 0 {
		t.Fatalf("expected no finding when no deserialization signal is present, got %d", len(findings))
	}
}
