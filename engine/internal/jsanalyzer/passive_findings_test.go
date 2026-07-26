package jsanalyzer

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/storage"
)

func TestEveryPassiveJavaScriptCategoryIsPublishedAndPersisted(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/passive-js.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureScan("scan-js-passive"); err != nil {
		t.Fatal(err)
	}

	var live []map[string]interface{}
	a := &Analyzer{
		scanID: "scan-js-passive", db: db,
		emit: func(eventType, _ string, payload map[string]interface{}) error {
			if eventType == "finding_detected" {
				live = append(live, payload)
			}
			return nil
		},
	}
	a.publishResult(AnalysisResult{
		JSURL:         "https://example.test/app.js",
		SourceMaps:    []SourceMapRef{{URL: "app.js.map", FromFile: "https://example.test/app.js", Confidence: 0.9}},
		Secrets:       []SecretMatch{{Kind: "github_token", Value: "ghp_1234567890abcdefghijklmnopqrstuvwxyz", Confidence: 0.9}},
		InternalPaths: []InternalPath{{Path: "./internal/admin-client", Kind: "internal", Confidence: 0.7}},
	})

	findings, err := db.ListFindings("scan-js-passive", 20, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 3 || len(live) != 3 {
		t.Fatalf("persisted=%d live=%d, want all three passive categories", len(findings), len(live))
	}
	reportClasses := map[string]int{}
	liveClasses := map[string]int{}
	for _, finding := range findings {
		reportClasses[finding.VulnClass]++
	}
	for _, payload := range live {
		liveClasses[payload["vuln_class"].(string)]++
		if payload["finding_id"].(int64) == 0 {
			t.Fatal("live finding must reference its persisted report record")
		}
	}
	for class, count := range reportClasses {
		if liveClasses[class] != count {
			t.Fatalf("category %q report=%d live=%d", class, count, liveClasses[class])
		}
	}
}
