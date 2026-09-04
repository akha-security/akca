package checkpoint

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/storage"
)

func TestComputeDelta(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/delta-test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}

	scan1 := "scan-baseline"
	scan2 := "scan-current"
	_ = db.EnsureScan(scan1)
	_ = db.EnsureScan(scan2)

	// Scan 1: Finding A (sqli), Finding B (xss)
	_, _ = db.SaveFinding(scan1, "SQL Injection", "critical", "sqli", "desc", "https://example.com/api", "id", 0.9, "{}")
	_, _ = db.SaveFinding(scan1, "Reflected XSS", "high", "xss", "desc", "https://example.com/search", "q", 0.8, "{}")

	// Scan 2: Finding A (sqli - stable), Finding C (ssrf - new). Finding B is fixed/resolved!
	_, _ = db.SaveFinding(scan2, "SQL Injection", "critical", "sqli", "desc", "https://example.com/api", "id", 0.9, "{}")
	_, _ = db.SaveFinding(scan2, "SSRF in Avatar", "high", "ssrf", "desc", "https://example.com/avatar", "url", 0.9, "{}")

	delta, err := ComputeDelta(db, scan1, scan2)
	if err != nil {
		t.Fatalf("unexpected delta error: %v", err)
	}

	if delta.TotalNew != 1 {
		t.Errorf("expected 1 new finding, got %d", delta.TotalNew)
	}
	if delta.TotalResolved != 1 {
		t.Errorf("expected 1 resolved finding, got %d", delta.TotalResolved)
	}
	if delta.TotalStable != 1 {
		t.Errorf("expected 1 stable finding, got %d", delta.TotalStable)
	}

	if delta.NewFindings[0].VulnClass != "ssrf" {
		t.Errorf("expected new finding to be SSRF, got: %s", delta.NewFindings[0].VulnClass)
	}
	if delta.ResolvedFindings[0].VulnClass != "xss" {
		t.Errorf("expected resolved finding to be XSS, got: %s", delta.ResolvedFindings[0].VulnClass)
	}
}
