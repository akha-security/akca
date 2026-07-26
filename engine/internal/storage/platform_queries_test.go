package storage

import "testing"

func TestCronHumanPreview(t *testing.T) {
	if got := CronHumanPreview("0 0 * * *"); got != "Daily at midnight" {
		t.Fatalf("unexpected preview: %s", got)
	}
}

func TestSeedBenchmarkIfEmpty(t *testing.T) {
	db, err := Open(t.TempDir() + "/akca.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := db.SeedBenchmarkIfEmpty(); err != nil {
		t.Fatal(err)
	}
	rows, err := db.ListBenchmarkResults(5)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 benchmark row, got %d", len(rows))
	}
}
