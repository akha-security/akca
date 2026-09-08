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

func TestHealthMetricsUI_RealValues(t *testing.T) {
	db, err := Open(t.TempDir() + "/akca.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}

	m, err := db.HealthMetricsUI("test-scan")
	if err != nil {
		t.Fatal(err)
	}
	if m.Goroutines <= 0 {
		t.Fatalf("expected positive goroutine count, got %d", m.Goroutines)
	}
	if m.MemoryMB <= 0 {
		t.Fatalf("expected positive memory measurement, got %f", m.MemoryMB)
	}
	if m.EngineStatus != "healthy" {
		t.Fatalf("unexpected engine status: %s", m.EngineStatus)
	}
}
