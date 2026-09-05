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
	findings := Analyze("customer payment card number: 4539 5787 6362 1486, expiry 12/29")
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

func TestAnalyzeCreditCardRejectsKnownFixturesAndMissingContext(t *testing.T) {
	for _, body := range []string{
		"test card number: 4111 1111 1111 1111",
		"order_id=4539578763621486",
		"card number: 1234 5678 9012 3452",
	} {
		for _, finding := range Analyze(body) {
			if finding.Kind == "credit_card" {
				t.Fatalf("false card finding for %q: %+v", body, finding)
			}
		}
	}
}

func TestAnalyzeIBANRequiresChecksumCountryLengthAndContext(t *testing.T) {
	findings := Analyze(`{"beneficiary_iban":"GB82 WEST 1234 5698 7654 32"}`)
	found := false
	for _, finding := range findings {
		if finding.Kind == "pii_iban" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected valid contextual IBAN, got %+v", findings)
	}
	for _, body := range []string{
		`{"iban":"GB82 WEST 1234 5698 7654 33"}`,
		`identifier=AB12123456789012345`,
		`documentation example IBAN: GB82 WEST 1234 5698 7654 32`,
	} {
		for _, finding := range Analyze(body) {
			if finding.Kind == "pii_iban" {
				t.Fatalf("false IBAN finding for %q: %+v", body, finding)
			}
		}
	}
}

func TestAnalyzeTurkishIBANWithReadableGrouping(t *testing.T) {
	findings := Analyze(`{"iban":"TR33 0006 1005 1978 6457 8413 26","beneficiary":"Caner Akca"}`)
	found := false
	for _, finding := range findings {
		if finding.Kind == "pii_iban" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected checksum-valid Turkish IBAN, got %+v", findings)
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

func TestPublicEmailIgnored(t *testing.T) {
	findings := Analyze("Contact us at support@mycompany.org or info@mycompany.org for help")
	for _, f := range findings {
		if f.Kind == "pii_email" {
			t.Fatalf("public support email must not be flagged as PII leak: %+v", f)
		}
	}
	personalFindings := Analyze("Personal contact: john.doe@company.org")
	found := false
	for _, f := range personalFindings {
		if f.Kind == "pii_email" {
			found = true
		}
	}
	if !found {
		t.Fatal("personal email should be flagged")
	}
}

func TestHTMLPIILabelIgnored(t *testing.T) {
	htmlPage := `<html><body><form><label>Date of Birth</label><input type="text"/></form></body></html>`
	findings := Analyze(htmlPage)
	for _, f := range findings {
		if f.Kind == "pii_context" {
			t.Fatalf("bare HTML label for Date of Birth must not be flagged: %+v", f)
		}
	}
	apiPayload := `{"date_of_birth": "1990-01-01"}`
	apiFindings := Analyze(apiPayload)
	found := false
	for _, f := range apiFindings {
		if f.Kind == "pii_context" {
			found = true
		}
	}
	if !found {
		t.Fatal("API payload with PII field should be flagged")
	}
}

