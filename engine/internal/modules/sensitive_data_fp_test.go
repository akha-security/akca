package modules

import (
	"context"
	"testing"

	"github.com/akha-security/akca/engine/internal/sensitivedata"
)

func TestSensitiveDataSignalConfirmationIsKindAndValueSpecific(t *testing.T) {
	body := `{"card_number":"4539578763621486","beneficiary_iban":"GB82WEST12345698765432"}`
	if !sensitiveDataSignalConfirmed(body, `{}`, "credit_card", "4539578763621486") {
		t.Fatal("expected exact card signal")
	}
	if sensitiveDataSignalConfirmed(body, `{}`, "credit_card", "GB82WEST12345698765432") {
		t.Fatal("IBAN must not satisfy card proof")
	}
	if sensitiveDataSignalConfirmed(body, body, "credit_card", "4539578763621486") {
		t.Fatal("baseline-identical data must not satisfy proof")
	}
}
func TestSensitiveDataRejectsHTMLSourceCodeSnippet(t *testing.T) {
	htmlBody := `<!doctype html>
<html>
<head><title>BeachBound - page not found</title></head>
<body>
<h2>PACKAGES</h2>
<script type="text/javascript">
function OptanonWrapper() { }
</script>
<p>Contact us at <a href="mailto:reservations@beachbound.com">reservations@beachbound.com</a> or ecommerce@applelg.net</p>
</body>
</html>`
	findings := sensitivedata.Analyze(htmlBody)
	for _, f := range findings {
		if f.Kind == "source_code_snippet" {
			t.Fatalf("standard HTML page with JavaScript function must not trigger source_code_snippet: %v", f)
		}
		if f.Kind == "pii_email" {
			t.Fatalf("public business/reservation email in HTML must not trigger pii_email: %v", f)
		}
	}
}

func TestGitContentRejectsHTMLContainingPackages(t *testing.T) {
	htmlBody := `<!doctype html><html><body><h2>PACKAGES</h2></body></html>`
	if isGitContent(htmlBody) {
		t.Fatal("HTML page containing the word PACKAGES must not be recognized as git content")
	}

	validPack := "PACK\x00\x00\x00\x02"
	if !isGitContent(validPack) {
		t.Fatal("valid PACK header must be recognized as git content")
	}

	validHead := "ref: refs/heads/main\n"
	if !isGitContent(validHead) {
		t.Fatal("valid ref: HEAD must be recognized as git content")
	}
}

func TestGitDeepRecoveryRejectsRedirectTo200(t *testing.T) {
	c := &groupDClient{
		responses: map[string]string{
			"/.git/HEAD": `<!doctype html><html><body><h2>PACKAGES</h2><script>function OptanonWrapper(){}</script></body></html>`,
		},
		statuses: map[string]int{"/.git/HEAD": 200},
	}
	target := ScanTarget{EndpointURL: "http://example.com/app", Method: "GET", Parameter: "q"}
	findings := groupDRunner(t, c).runGitDeepRecovery(context.Background(), target)
	if len(findings) > 0 {
		for _, f := range findings {
			if f.VulnClass == "git_recovery" {
				t.Fatalf("HTML 200 soft-404 must not trigger git_recovery finding: %s", f.Title)
			}
		}
	}
}
