package crawler

import (
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/testfixtures"
)

func TestPassiveSecretIsPublishedAndPersisted(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/passive-secret.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureScan("scan-passive"); err != nil {
		t.Fatal(err)
	}

	var live []map[string]interface{}
	c := &Crawler{
		scanID: "scan-passive", db: db, secretsSeen: make(map[string]struct{}),
		emit: func(eventType, _ string, payload map[string]interface{}) error {
			if eventType == "finding_detected" {
				live = append(live, payload)
			}
			return nil
		},
	}
	raw := testfixtures.GitHubToken()
	c.scanSecrets("https://example.test/config.json", `{"token":"`+raw+`"}`)

	findings, err := db.ListFindings("scan-passive", 20, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || len(live) != 1 {
		t.Fatalf("persisted=%d live=%d, want one of each", len(findings), len(live))
	}
	if findings[0].VulnClass != "secret_exposure" || live[0]["vuln_class"] != "secret_exposure" {
		t.Fatalf("category mismatch: report=%q live=%v", findings[0].VulnClass, live[0]["vuln_class"])
	}
	if live[0]["payload_str"] != raw || !strings.Contains(findings[0].EvidenceJSON, raw) {
		t.Fatal("live and report evidence must both contain the exact detected value")
	}
	technical := storage.ParseEvidenceBody(findings[0].EvidenceJSON)
	if technical.Payload != raw || technical.Signal != "github_token" {
		t.Fatalf("incomplete report evidence: %+v", technical)
	}
}
