package modules

import (
	"context"
	"testing"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/payloadgen"
)

func TestPickSQLiAttemptPrefersErrorBodyOverEmptySurface(t *testing.T) {
	errBody := `{"error":"You have an error in your SQL syntax near '' OR '1'='1'"}`
	base := `{"id":1,"name":"alice"}`
	attempts := []InjectionAttempt{
		{
			Surface: "form",
			Target:  ScanTarget{EndpointURL: "http://lab.test/api/users", Method: "POST", Parameter: "id", Location: "form"},
			RR:      httpclientRR("", 200),
		},
		{
			Surface: "native:query",
			Target:  ScanTarget{EndpointURL: "http://lab.test/api/users", Method: "GET", Parameter: "id", Location: "query"},
			RR:      httpclientRR(errBody, 500),
		},
	}
	got := pickSQLiAttempt(attempts, base, attempts[1].Target)
	if got.RR.Response.Body != errBody {
		t.Fatalf("expected SQL error attempt, got %q", got.RR.Response.Body)
	}
}

func TestRunIntegrationSubsetLabSQLi(t *testing.T) {
	errBody := `{"error":"You have an error in your SQL syntax near '' OR '1'='1'"}`
	c := &groupBClient{
		responses: map[string]string{
			"akca-sqli-base": `{"id":1,"name":"alice"}`,
			`' OR '1'='1`:    errBody,
			`'`:              errBody,
		},
		statuses: map[string]int{
			`' OR '1'='1`: 500,
			`'`:           500,
		},
	}
	target := ScanTarget{
		EndpointURL: "http://lab.test/api/users",
		Method:      "GET",
		Parameter:   "id",
		Location:    "query",
		Payloads: payloadgen.GenerationResult{Payloads: []payloadgen.Payload{
			{VulnClass: "sqli", Value: `' OR '1'='1`, Variant: "error", ExpectedSignal: "sql_error", Priority: 10, BudgetCost: 1},
		}},
	}
	findings := groupBRunner(t, c).runSQLi(context.Background(), target)
	if len(findings) == 0 {
		t.Fatal("expected sqli finding for lab-style SQL error response")
	}
}

func TestRunIntegrationSubsetLabSQLiViaSubset(t *testing.T) {
	errBody := `{"error":"You have an error in your SQL syntax near '' OR '1'='1'"}`
	c := &groupBClient{
		responses: map[string]string{
			"akca-sqli-base": `{"id":1,"name":"alice"}`,
			`' OR '1'='1`:    errBody,
			`'`:              errBody,
		},
		statuses: map[string]int{
			`' OR '1'='1`: 500,
			`'`:           500,
		},
	}
	target := ScanTarget{
		EndpointURL: "http://lab.test/api/users",
		Method:      "GET",
		Parameter:   "id",
		Location:    "query",
		Payloads: payloadgen.GenerationResult{Payloads: []payloadgen.Payload{
			{VulnClass: "sqli", Value: `' OR '1'='1`, Variant: "error", ExpectedSignal: "sql_error", Priority: 10, BudgetCost: 1},
		}},
	}
	findings, err := groupBRunner(t, c).RunIntegrationSubset(context.Background(), []ScanTarget{target})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected sqli finding via integration subset")
	}
}

func httpclientRR(body string, status int) httpclient.RequestResponse {
	return httpclient.RequestResponse{
		Response: httpclient.ResponseRecord{StatusCode: status, Body: body, Headers: map[string]string{"Content-Type": "application/json"}},
	}
}
