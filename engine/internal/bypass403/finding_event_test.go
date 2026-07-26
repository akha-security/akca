package bypass403

import (
	"testing"
	"time"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/storage"
)

func TestVerifiedBypassIsPublishedAndPersisted(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/finding-event.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureScan("scan-bypass-live"); err != nil {
		t.Fatal(err)
	}

	var live map[string]interface{}
	engine := &Engine{
		scanID: "scan-bypass-live", db: db,
		emit: func(eventType, _ string, payload map[string]interface{}) error {
			if eventType == "finding_detected" {
				live = payload
			}
			return nil
		},
	}
	err = engine.createFinding(AttemptResult{
		Baseline:  Baseline{URL: "https://example.test/admin", Method: "GET", StatusCode: 403},
		Attempt:   Attempt{Category: ForwardedURLHeader, Label: "X-Original-URL", Method: "GET", URL: "https://example.test/admin"},
		Request:   httpclient.RequestRecord{Method: "GET", URL: "https://example.test/admin"},
		Response:  httpclient.ResponseRecord{StatusCode: 200, Duration: 75 * time.Millisecond},
		Succeeded: true, Reason: "ok_access",
	})
	if err != nil {
		t.Fatal(err)
	}

	findings, err := db.ListFindings("scan-bypass-live", 20, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || live == nil {
		t.Fatalf("persisted=%d live=%v", len(findings), live != nil)
	}
	if live["vuln_class"] != findings[0].VulnClass || live["response_status"] != 200 {
		t.Fatalf("report/live mismatch: report=%+v live=%v", findings[0], live)
	}
	technical := storage.ParseEvidenceBody(findings[0].EvidenceJSON)
	if technical.Signal != string(ForwardedURLHeader) || technical.Payload != "X-Original-URL" {
		t.Fatalf("incomplete report evidence: %+v", technical)
	}
}
