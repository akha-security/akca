package learning_test

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/learning"
	"github.com/akha-security/akca/engine/internal/storage"
)

func TestProfileRecordAndBlock(t *testing.T) {
	p := learning.NewProfile("example.com", "http://example.com/search")
	p = p.Record("xss", learning.OutcomeWorked)
	p = p.Record("sqli", learning.OutcomeWAFBlocked)
	if !p.IsBlocked("sqli") {
		t.Fatal("sqli should be blocked")
	}
	if p.BoostPriority("xss", 50) != 60 {
		t.Fatal("expected boost for worked family")
	}
}

func TestExportImport(t *testing.T) {
	p := learning.NewProfile("example.com", "")
	p = p.Record("xss", learning.OutcomeFalsePositive)
	raw, err := p.ExportJSON()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := learning.ImportJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.FalsePositive) != 1 || loaded.FalsePositive[0] != "xss" {
		t.Fatalf("import mismatch: %+v", loaded)
	}
}

func TestStorePersistence(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/learn.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_ = db.Migrate()
	_ = db.EnsureScan("scan-learn")

	store := learning.NewStore(db)
	if err := store.RecordOutcome("example.com", "http://example.com/a", "xss", learning.OutcomeWorked); err != nil {
		t.Fatal(err)
	}
	p := store.Load("example.com", "http://example.com/a")
	if len(p.Worked) != 1 {
		t.Fatalf("expected worked payload family, got %+v", p.Worked)
	}
	raw, err := store.Export("example.com", "http://example.com/a")
	if err != nil || len(raw) == 0 {
		t.Fatal("export failed")
	}
	if err := store.Import(raw); err != nil {
		t.Fatal(err)
	}
}

func TestMergeProfiles(t *testing.T) {
	a := learning.NewProfile("example.com", "")
	a = a.Record("xss", learning.OutcomeWorked)
	b := learning.NewProfile("example.com", "/api")
	b = b.Record("sqli", learning.OutcomeWAFBlocked)
	m := learning.Merge(a, b)
	if len(m.Worked) != 1 || len(m.Blocked) != 1 {
		t.Fatalf("merge failed: %+v", m)
	}
}
