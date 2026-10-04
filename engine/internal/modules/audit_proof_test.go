package modules

import (
	"context"
	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"testing"
)

func TestSQLi400RequiresVendorEvidence(t *testing.T) {
	p := defaultPayload("sqli", "quote", "'", "sql_error")
	base := httpclient.ResponseRecord{StatusCode: 200, Body: "product"}
	for _, tc := range []struct {
		body string
		want bool
	}{
		{"Bad Request", false}, {"SyntaxError: unexpected token", false},
		{"sqlite3.OperationalError: near quote: syntax error", true},
	} {
		got := sqliFindingAllowed(p, "error_based", base, httpclient.ResponseRecord{StatusCode: 400, Body: tc.body}, "")
		if got != tc.want {
			t.Fatalf("body=%q allowed=%v", tc.body, got)
		}
	}
}

func TestAutonomousRateLimitRequiresVerifiedAuthenticationFailures(t *testing.T) {
	for _, tc := range []struct {
		body string
		want int
	}{{"invalid credentials", 1}, {"Bad Request", 0}, {"generic page", 0}} {
		r := groupCRunner(t, &groupCClient{responses: map[string]string{"__default__": tc.body}})
		r.cfg.PayloadBudget = config.PayloadBudgetHigh
		findings := r.runRateLimit(context.Background(), ScanTarget{EndpointURL: "http://example.com/login", Method: "GET", Parameter: "user", Location: "query"})
		if len(findings) != tc.want {
			t.Fatalf("body=%q findings=%d want=%d", tc.body, len(findings), tc.want)
		}
	}
}
