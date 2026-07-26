package modules

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/verification"
)

func TestPersistFindingPublishesExactlyOneCanonicalEvent(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/module-finding-event.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureScan("scan-module-live"); err != nil {
		t.Fatal(err)
	}

	var events []map[string]interface{}
	runner := &Runner{
		scanID: "scan-module-live", db: db,
		emit: func(eventType, _ string, payload map[string]interface{}) error {
			if eventType == "finding_detected" {
				events = append(events, payload)
			}
			return nil
		},
	}
	finding := ModuleFinding{
		Title: "Advanced SQL injection", VulnClass: "sqli", Severity: "Critical",
		Description: "confirmed union signal", Endpoint: "https://example.test/items?id=1",
		Parameter: "id", Location: "query", Confidence: verification.Confirmed,
		Evidence: Evidence{
			Module: "sqli", Signal: "union_signal",
			Payload:  payloadgen.Payload{Value: "' UNION SELECT 1,2-- -", VulnClass: "sqli"},
			Request:  httpclient.RequestRecord{Method: "GET", URL: "https://example.test/items?id=1"},
			Response: httpclient.ResponseRecord{StatusCode: 200},
			Verification: verification.Result{
				Confidence: verification.Confirmed, Score: 0.95,
				ProofType:   verification.ProofDifferentialReplay,
				ProofPolicy: verification.CurrentProofPolicyVersion, ProofSatisfied: true,
				Observations: []verification.Observation{
					verification.NewHTTPObservation(
						"scan-module-live", "sqli", "https://example.test/items?id=1", "id", "query",
						verification.RolePositiveProbe, 1, "", "GET",
						"https://example.test/items?id=1", "", nil,
						verification.ResponseSnapshot{StatusCode: 200, Body: "union marker"},
					),
				},
			},
		},
	}
	if err := runner.persistFinding(finding); err != nil {
		t.Fatal(err)
	}

	findings, err := db.ListFindings("scan-module-live", 20, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || len(events) != 1 {
		t.Fatalf("persisted=%d live=%d, want exactly one of each", len(findings), len(events))
	}
	if events[0]["finding_id"] != findings[0].ID || events[0]["signal"] != "union_signal" {
		t.Fatalf("report/live mismatch: report=%+v live=%v", findings[0], events[0])
	}
}
