package storage

import (
	"path/filepath"
	"testing"
)

func TestListFindingsUIAndAnnotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "akca.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	scanID := "scan-ui"
	_ = db.EnsureScan(scanID)
	_ = db.SeedFindingForTest(scanID, "XSS", "high", "Confirmed", "xss", "Reflected XSS in search param", "https://ex.com/s")
	rows, _, err := db.ListFindingsUI(FindingQuery{ScanID: scanID, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(rows))
	}
	if rows[0].Description == "" {
		t.Fatal("expected description populated")
	}
	if err := db.SaveAnnotation(rows[0].ID, "Confirmed", "verified manually", "tester"); err != nil {
		t.Fatal(err)
	}
	detail, err := db.GetFindingDetailUI(rows[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Impact == "" || detail.Remediation == "" {
		t.Fatal("expected impact and remediation")
	}
	if detail.Status != "Confirmed" {
		t.Fatalf("expected Confirmed status, got %s", detail.Status)
	}
}

func TestListFindingsUICursorPagination(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "akca.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	scanID := "scan-page"
	_ = db.EnsureScan(scanID)
	for i := 0; i < 120; i++ {
		if err := db.SeedFindingForTest(scanID, "F", "low", "Potential", "xss", "d", "https://x"); err != nil {
			t.Fatal(err)
		}
	}
	var total int
	cursor := int64(0)
	for {
		rows, next, err := db.ListFindingsUI(FindingQuery{ScanID: scanID, Limit: 25, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		total += len(rows)
		if next == 0 {
			break
		}
		cursor = next
	}
	if total != 120 {
		t.Fatalf("expected 120 findings via cursor pagination, got %d", total)
	}
}

func TestTargetMapUIEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "akca.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	nodes, err := db.TargetMapUI("scan-empty")
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) == 0 {
		t.Fatal("expected placeholder node")
	}
}

func TestListEvidenceLazyFromEmbeddedDescription(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "akca.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	scanID := "scan-ev"
	_ = db.EnsureScan(scanID)
	evJSON := `{"module":"command_injection","signal":"separator_output","payload":{"value":";id"},"request":{"method":"GET","url":"https://ex.com/?q=1","headers":{"Host":"ex.com"},"body":""},"response":{"status_code":200,"headers":{},"body":"uid=0(root)","duration":120000000}}`
	desc := "separator_output at https://ex.com/?q=1\n\nevidence: " + evJSON
	findingID, err := db.SaveFinding(scanID, "Command Injection", "high", "command_injection", desc, "https://ex.com/?q=1", "q", 0.8, "")
	if err != nil {
		t.Fatal(err)
	}
	items, err := db.ListEvidenceLazy("", findingID)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || !items[0].HasBody {
		t.Fatalf("expected synthetic evidence item, got %+v", items)
	}
	body, err := db.LoadEvidenceBody(-findingID)
	if err != nil {
		t.Fatal(err)
	}
	if body.Payload != ";id" || body.RawRequest == "" || body.RawResponse == "" {
		t.Fatalf("expected parsed HTTP proof, got %+v", body)
	}
}
