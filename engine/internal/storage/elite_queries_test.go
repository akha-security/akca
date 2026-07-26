package storage

import "testing"

func TestEliteQueriesRoundTrip(t *testing.T) {
	db, err := Open(t.TempDir() + "/akca.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	_ = db.EnsureScan("scan-elite")
	if err := db.SaveCheckpoint("scan-elite", `{"phase":"crawl"}`); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveHealthSnapshot("scan-elite", `{"goroutines":10}`); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveComparisonDiff("a", "b", `{"new_count":1}`); err != nil {
		t.Fatal(err)
	}
	cps, err := db.ListCheckpointRecords("scan-elite", 1)
	if err != nil || len(cps) == 0 {
		t.Fatalf("checkpoint missing: %v", err)
	}
}
