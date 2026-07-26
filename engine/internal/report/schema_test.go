package report

import "testing"

func TestValidateJSONSchema(t *testing.T) {
	valid := []byte(`{
		"schema_version":"1.0","generated_at":"2026-01-01T00:00:00Z",
		"template":"internal","format":"json","partial":false,
		"title":"Akca","summary":"scan","scope":{"scan_id":"scan-1"},
		"metrics":{"total_findings":0},"findings":[]
	}`)
	if err := ValidateJSONSchema(valid); err != nil {
		t.Fatal(err)
	}
	invalid := []byte(`{"schema_version":"0.9","format":"json"}`)
	if err := ValidateJSONSchema(invalid); err == nil {
		t.Fatal("incompatible report schema was accepted")
	}
}

func TestValidateJSONSchemaRejectsUnprovenPrimaryFinding(t *testing.T) {
	raw := []byte(`{
		"schema_version":"1.0","generated_at":"2026-01-01T00:00:00Z",
		"template":"hackerone","format":"json","partial":false,
		"title":"Akca","summary":"scan","scope":{"scan_id":"scan-1"},
		"metrics":{"total_findings":1},"findings":[{
			"id":1,"title":"SQL Injection","summary":"","description":"heuristic",
			"severity":"critical","confidence":"Confirmed","confidence_score":0.99,
			"vuln_class":"sqli","endpoint_url":"https://example.test/",
			"http_evidence":{"proof_satisfied":false}
		}]
	}`)
	if err := ValidateJSONSchema(raw); err == nil {
		t.Fatal("unproven primary finding passed the stable report schema")
	}
}
