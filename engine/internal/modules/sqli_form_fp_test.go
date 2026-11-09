package modules

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

// A validation/filter layer can classify equality-shaped input without SQL.
// Both operand sets and all replays are stable, as in the reported form case.
func TestSQLiRegisterFormEqualityFilterIsNotSQLExecution(t *testing.T) {
	for _, parameter := range []string{"city", "email"} {
		for _, reverse := range []bool{false, true} {
			t.Run(parameter+map[bool]string{false: "/normal", true: "/reverse"}[reverse], func(t *testing.T) {
				base := `<html><title>Giriş</title><form method="post" action="/auth/register"><input name="email"><input type="password" name="password"><button>Hesap Oluştur</button></form></html>`
				rejected := strings.Replace(base, "<form", `<p>İstek doğrulaması başarısız. Girdi biçimini kontrol ederek yeniden deneyin.</p><form`, 1)
				equality := regexp.MustCompile(`['"]?([0-9]+)['"]?\s*=\s*['"]?([0-9]+)['"]?`)
				complementaryRequests := 0
				client := auditDoer(func(_ context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
					fields, _ := url.ParseQuery(string(body))
					value := fields.Get(parameter)
					if strings.Contains(value, "<>") {
						complementaryRequests++
					}
					response := base
					if match := equality.FindStringSubmatch(value); len(match) > 0 {
						isEqual := match[1] == match[2]
						if isEqual == reverse {
							response = rejected
						}
					}
					return httpclient.RequestResponse{Request: httpclient.RequestRecord{Method: method, URL: rawURL, Body: string(body), Headers: headers}, Response: httpclient.ResponseRecord{StatusCode: 200, Body: response, Headers: map[string]string{"Content-Type": "text/html"}}}, nil
				})
				target := ScanTarget{EndpointURL: "https://example.test/auth/register", Method: "POST", Location: "form", Parameter: parameter, BodyTemplate: "city=akca&email=test%40example.com&password=example"}
				if findings := newSQLiLabRunner(client).booleanBlindSQLiProbe(context.Background(), target, baselineRR(target, base)); len(findings) > 0 {
					t.Fatalf("form/filter response produced SQLi finding: %+v", findings)
				}
				if complementaryRequests == 0 {
					t.Fatal("fixture never reached the equality-only false-positive decision")
				}
			})
		}
	}
}
