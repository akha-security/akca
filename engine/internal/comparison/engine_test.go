package comparison

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/storage"
)

func TestCompareFindingsAndEndpoints(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/akca.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	prev, curr := "scan-prev", "scan-curr"
	_ = db.EnsureScan(prev)
	_ = db.EnsureScan(curr)
	_ = db.SeedFindingForTest(prev, "Old XSS", "high", "firm", "xss", "", "https://a.test/1")
	_ = db.SeedFindingForTest(prev, "Gone", "low", "firm", "info", "", "https://a.test/2")
	_ = db.SeedFindingForTest(curr, "Old XSS", "critical", "firm", "xss", "", "https://a.test/1")
	_ = db.SeedFindingForTest(curr, "New IDOR", "high", "firm", "idor", "", "https://a.test/3")
	_ = db.SeedEndpointForTest(prev, "https://a.test/1")
	_ = db.SeedEndpointForTest(curr, "https://a.test/1")
	_ = db.SeedEndpointForTest(curr, "https://a.test/9")

	diff, err := NewEngine(db).Compare(prev, curr)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.NewFindings) == 0 || len(diff.ChangedFindings) == 0 || len(diff.ResolvedFindings) == 0 {
		t.Fatalf("expected new/changed/resolved: %+v", diff)
	}
	if len(diff.NewEndpoints) == 0 {
		t.Fatal("expected new endpoint")
	}
}
