package policy

import (
	"path/filepath"
	"testing"

	"github.com/akha-security/akca/engine/internal/storage"
)

func TestPolicyUsesProofGateAndPersistsTrend(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "akca.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	for _, scanID := range []string{"previous", "current"} {
		if err := db.EnsureScan(scanID); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.SeedFindingForTest("previous", "Existing XSS", "medium", "Confirmed",
		"xss", "", "https://example.test/a"); err != nil {
		t.Fatal(err)
	}
	if err := db.SeedFindingForTest("current", "Existing XSS", "medium", "Confirmed",
		"xss", "", "https://example.test/a"); err != nil {
		t.Fatal(err)
	}
	if err := db.SeedFindingForTest("current", "New SQLi", "high", "Confirmed",
		"sqli", "", "https://example.test/b"); err != nil {
		t.Fatal(err)
	}
	if err := db.SeedFindingForTest("current", "False confirmed label", "critical", "Confirmed",
		"sqli", "", "https://example.test/c"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Conn().Exec(`
UPDATE findings SET evidence_json =
  '{"verification":{"proof_satisfied":true,"proof_type":"differential"}}'
WHERE title IN ('Existing XSS','New SQLi')`); err != nil {
		t.Fatal(err)
	}
	_ = db.SeedEndpointForTest("previous", "https://example.test/a")
	_ = db.SeedEndpointForTest("current", "https://example.test/a")
	_ = db.SeedEndpointForTest("current", "https://example.test/b")

	evaluation, err := Evaluate(db, "current", "previous", DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if evaluation.Passed || len(evaluation.NewConfirmed) != 1 ||
		evaluation.NewConfirmed[0].Title != "New SQLi" ||
		evaluation.UnprovenLabeledConfirmed != 1 || evaluation.Trend.NewEndpoints != 1 {
		t.Fatalf("unexpected proof-aware policy: %+v", evaluation)
	}
	var saved int
	if err := db.Conn().QueryRow(`SELECT COUNT(*) FROM policy_evaluations WHERE current_scan_id = 'current'`).Scan(&saved); err != nil || saved != 1 {
		t.Fatalf("evaluation not persisted: %d %v", saved, err)
	}
}
