package sensitivedata

import "testing"

func TestAnalyzeSSN(t *testing.T) {
	findings := Analyze("patient ssn 123-45-6789")
	if len(findings) == 0 {
		t.Fatal("expected SSN finding")
	}
	if findings[0].Kind != "pii_ssn" {
		t.Fatalf("kind=%q", findings[0].Kind)
	}
}

func TestAnalyzeCreditCardLuhn(t *testing.T) {
	findings := Analyze("card: 4111 1111 1111 1111")
	found := false
	for _, f := range findings {
		if f.Kind == "credit_card" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected Luhn-valid credit card finding")
	}
}

func TestAnalyzeJWT(t *testing.T) {
	body := "token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	findings := Analyze(body)
	found := false
	for _, f := range findings {
		if f.Kind == "jwt_token" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected jwt finding")
	}
}

func TestAnalyzeStackTrace(t *testing.T) {
	findings := Analyze("Exception in thread main\n\tat com.example.App.main(App.java:12)")
	if len(findings) == 0 {
		t.Fatal("expected stack trace finding")
	}
}

func TestAnalyzeInternalIP(t *testing.T) {
	findings := Analyze("upstream http://10.20.30.40/internal")
	found := false
	for _, f := range findings {
		if f.Kind == "internal_ip" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected internal ip finding")
	}
}

func TestLuhnInvalid(t *testing.T) {
	findings := Analyze("number 4111 1111 1111 1112")
	for _, f := range findings {
		if f.Kind == "credit_card" {
			t.Fatal("invalid card should not match")
		}
	}
}
