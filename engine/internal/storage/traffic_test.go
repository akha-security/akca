package storage

import (
	"strings"
	"testing"
	"time"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

func TestSaveRequestResponsePreservesFullRedactedTraffic(t *testing.T) {
	db, err := Open(t.TempDir() + "/traffic.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureScan("scan-traffic"); err != nil {
		t.Fatal(err)
	}
	rr := httpclient.RequestResponse{
		Request: httpclient.RequestRecord{Method: "POST", URL: "https://example.com/api", Headers: map[string]string{
			"Accept": "application/json", "Content-Type": "application/json", "Authorization": "[REDACTED]",
		}, Body: `{"name":"akca"}`},
		Response: httpclient.ResponseRecord{StatusCode: 201, Headers: map[string]string{"Content-Type": "application/json", "Set-Cookie": "[REDACTED]"}, Body: `{"ok":true}`, Duration: 125 * time.Millisecond},
	}
	if _, err := db.SaveRequestResponse("scan-traffic", nil, rr); err != nil {
		t.Fatal(err)
	}
	records, err := db.ListRequestResponses("scan-traffic", 10)
	if err != nil || len(records) != 1 {
		t.Fatalf("records=%d err=%v", len(records), err)
	}
	rawRequest, rawResponse := RawHTTPFromRecord(records[0])
	for _, want := range []string{"POST /api HTTP/1.1", "Host: example.com", "Accept: application/json", "Content-Type: application/json", `{"name":"akca"}`} {
		if !strings.Contains(rawRequest, want) {
			t.Fatalf("raw request missing %q:\n%s", want, rawRequest)
		}
	}
	if !strings.Contains(rawResponse, "HTTP/1.1 201") || !strings.Contains(rawResponse, `{"ok":true}`) {
		t.Fatalf("unexpected raw response:\n%s", rawResponse)
	}
}
