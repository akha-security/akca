package observability

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/storage"
)

func TestCollectorCapture(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/akca.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	c := NewCollector(db)
	c.RecordRequest(false)
	c.SetBacklog(3)
	snap, err := c.Capture("scan-h", map[string]float64{"crawler": 1.2}, "listening", map[string]int{"crawl": 2, "browser": 1})
	if err != nil {
		t.Fatal(err)
	}
	if snap.Goroutines <= 0 || snap.EngineStatus != "healthy" {
		t.Fatalf("unexpected snapshot: %+v", snap)
	}
	rows, err := db.ListHealthSnapshotRecords("scan-h", 5)
	if err != nil || len(rows) == 0 {
		t.Fatalf("health snapshot not persisted: %v", err)
	}
}
