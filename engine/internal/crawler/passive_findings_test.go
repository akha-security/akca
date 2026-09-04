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

func TestPassiveSupplyChainDetection(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/supply-chain.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureScan("scan-sc"); err != nil {
		t.Fatal(err)
	}

	var live []map[string]interface{}
	c := &Crawler{
		scanID: "scan-sc", db: db, secretsSeen: make(map[string]struct{}),
		emit: func(eventType, _ string, payload map[string]interface{}) error {
			if eventType == "finding_detected" {
				live = append(live, payload)
			}
			return nil
		},
	}
	c.scanSupplyChain("https://example.test/index.html", `<script src="https://polyfill.io/v3/polyfill.min.js"></script>`)

	findings, err := db.ListFindings("scan-sc", 20, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || len(live) != 1 {
		t.Fatalf("persisted=%d live=%d, want 1 finding", len(findings), len(live))
	}
	if findings[0].VulnClass != "supply_chain" || live[0]["vuln_class"] != "supply_chain" {
		t.Fatalf("category mismatch: %s", findings[0].VulnClass)
	}
	if !strings.Contains(findings[0].EvidenceJSON, "polyfill.io") {
		t.Fatalf("evidence must contain polyfill.io: %s", findings[0].EvidenceJSON)
	}
}

func TestSupplyChainRequiresActualURLReference(t *testing.T) {
	if responseReferencesDomain("Documentation mentions polyfill.io but does not load it.", "polyfill.io") {
		t.Fatal("a textual domain mention must not produce a supply-chain finding")
	}
	if responseReferencesDomain(`<script src="https://notpolyfill.io/app.js"></script>`, "polyfill.io") {
		t.Fatal("lookalike domain must not produce a supply-chain finding")
	}
	if !responseReferencesDomain(`<script src="//cdn.polyfill.io/v3/polyfill.js"></script>`, "polyfill.io") {
		t.Fatal("a protocol-relative script reference should be detected")
	}
}

func TestPassiveThirdPartyScriptRequiresSRI(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/sri.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureScan("scan-sri"); err != nil {
		t.Fatal(err)
	}
	c := &Crawler{scanID: "scan-sri", db: db, secretsSeen: make(map[string]struct{}), emit: func(string, string, map[string]interface{}) error { return nil }}
	c.scanThirdPartyScriptIntegrity("https://app.example.test/index.html", `<script src="https://cdn.example.test/app.js"></script><script src="/local.js"></script>`)

	findings, err := db.ListFindings("scan-sri", 20, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || !strings.Contains(findings[0].EvidenceJSON, "cdn.example.test/app.js") {
		t.Fatalf("got %+v, want one third-party SRI finding", findings)
	}

	c.scanThirdPartyScriptIntegrity("https://app.example.test/index.html", `<script src="https://cdn.example.test/app.js" integrity="sha384-valid"></script>`)
	findings, err = db.ListFindings("scan-sri", 20, 0)
	if err != nil || len(findings) != 1 {
		t.Fatalf("integrity-protected script must not add a finding: count=%d err=%v", len(findings), err)
	}
}
