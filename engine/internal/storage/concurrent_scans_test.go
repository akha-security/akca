package storage

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

func TestIndependentConnectionsPersistDistinctScans(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concurrent-scans.db")
	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if err := first.Migrate(); err != nil {
		t.Fatal(err)
	}

	second, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	const scansPerConnection = 25
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for worker, db := range []*DB{first, second} {
		wg.Add(1)
		go func(worker int, db *DB) {
			defer wg.Done()
			<-start
			for i := 0; i < scansPerConnection; i++ {
				if err := db.EnsureScan(fmt.Sprintf("scan-worker-%d-%d", worker, i)); err != nil {
					errs <- err
					return
				}
			}
		}(worker, db)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent scan persistence failed: %v", err)
	}

	var count int
	if err := first.Conn().QueryRow(`SELECT COUNT(*) FROM scans`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if want := scansPerConnection * 2; count != want {
		t.Fatalf("persisted scan count = %d, want %d", count, want)
	}
}
