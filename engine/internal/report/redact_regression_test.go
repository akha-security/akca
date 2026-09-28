package report

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRedactionIncludesNestedEvidenceWithoutChangingRawCopy(t *testing.T) {
	f := FindingEntry{ID: 9007199254740993, Description: "api_key=private-key", ReproductionSteps: []string{"Authorization: Bearer private-token"}, HTTPEvidence: HTTPEvidence{RawRequest: "X-API-Key: private-cookie\r\n", RawResponse: `{"password":"private-password"}`, URL: "https://example.test/?token=private-query"}}
	raw := f
	RedactFinding(&f)
	encoded, _ := json.Marshal(f)
	if strings.Contains(string(encoded), "private-") {
		t.Fatalf("secret survived: %s", encoded)
	}
	if f.ID != raw.ID {
		t.Fatal("redaction changed numeric identity")
	}
	if raw.ReproductionSteps[0] != "Authorization: Bearer private-token" {
		t.Fatal("redaction mutated raw evidence")
	}
}

func TestCookieHeadersNotRedacted(t *testing.T) {
	f := FindingEntry{
		ID:          1,
		Title:       "Sensitive cookie missing Secure flag",
		Description: "Cookie session missing secure attribute",
		HTTPEvidence: HTTPEvidence{
			RawRequest:  "Cookie: session=abc; user_id=123\r\n",
			RawResponse: "Set-Cookie: session=abc; Path=/; HttpOnly\r\n",
		},
	}
	RedactFinding(&f)
	if !strings.Contains(f.HTTPEvidence.RawRequest, "Cookie: session=abc") {
		t.Fatalf("cookie header was unexpectedly redacted: %s", f.HTTPEvidence.RawRequest)
	}
	if !strings.Contains(f.HTTPEvidence.RawResponse, "Set-Cookie: session=abc") {
		t.Fatalf("set-cookie header was unexpectedly redacted: %s", f.HTTPEvidence.RawResponse)
	}
}
