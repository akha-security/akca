package storage

import (
	"path/filepath"
	"testing"
)

func TestMigrationCreatesAllTables(t *testing.T) {
	path := filepath.Join(t.TempDir(), "akca.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.Migrate(); err != nil {
		t.Fatalf("migrate failed: %v", err)
	}
	ok, missing, err := db.HasAllRequiredTables()
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("missing tables: %v", missing)
	}

	for _, table := range RequiredTables() {
		if table == "schema_migrations" {
			continue
		}
		var name string
		err := db.Conn().QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name = ?`, table).Scan(&name)
		if err != nil {
			t.Fatalf("table %s not found: %v", table, err)
		}
	}
}

func TestMigrationIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "akca.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatalf("second migrate failed: %v", err)
	}
	v, err := db.CurrentVersion()
	if err != nil {
		t.Fatal(err)
	}
	if v != 15 {
		t.Fatalf("expected version 15, got %d", v)
	}
}

func TestMigrationRemovesRetiredReconTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "akca.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := db.Rollback(5); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.Conn().QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='subdomain_results'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("retired reconnaissance table still exists")
	}
}

func TestMigrationRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "akca.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := db.Rollback(0); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
	ok, _, err := db.HasAllRequiredTables()
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected tables removed after rollback")
	}
}
