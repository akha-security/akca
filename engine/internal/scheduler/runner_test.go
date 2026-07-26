package scheduler

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/storage"
)

func TestScheduledRunExecution(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/akca.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	cfg, _ := json.Marshal(config.DefaultScanConfig())
	if err := db.SaveScheduledScan("s1", "0 0 * * *", string(cfg), true); err != nil {
		t.Fatal(err)
	}
	_ = db.MarkScheduleDue("s1", time.Now().Add(-time.Minute).UTC().Format(time.RFC3339))
	started := make(chan struct{}, 1)
	r := NewRunner(db, func(c config.ScanConfig) error {
		started <- struct{}{}
		return nil
	})
	r.pollDue()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("expected scheduled start")
	}
}

func TestScheduledRunWaitsForCompletion(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/akca.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	cfg, _ := json.Marshal(config.DefaultScanConfig())
	if err := db.SaveScheduledScan("s2", "0 0 * * *", string(cfg), true); err != nil {
		t.Fatal(err)
	}
	_ = db.MarkScheduleDue("s2", time.Now().Add(-time.Minute).UTC().Format(time.RFC3339))
	done := make(chan struct{})
	r := NewRunner(db, func(c config.ScanConfig) error {
		time.Sleep(200 * time.Millisecond)
		close(done)
		return nil
	})
	r.pollDue()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("scheduled starter did not run")
	}
	time.Sleep(100 * time.Millisecond)
	runs, err := db.ListScheduledRuns("s2", 1)
	if err != nil || len(runs) == 0 {
		t.Fatalf("expected scheduled run record")
	}
	if runs[0].Status != "completed" {
		t.Fatalf("expected completed status after blocking starter, got %s", runs[0].Status)
	}
}

func TestRunnerLifecycle(t *testing.T) {
	db, _ := storage.Open(t.TempDir() + "/akca.db")
	defer db.Close()
	_ = db.Migrate()
	r := NewRunner(db, nil)
	ctx, cancel := context.WithCancel(context.Background())
	go r.Start(ctx)
	time.Sleep(50 * time.Millisecond)
	cancel()
	r.Stop()
}

func TestRunnerStopIdempotency(t *testing.T) {
	db, _ := storage.Open(t.TempDir() + "/akca_stop.db")
	defer db.Close()
	_ = db.Migrate()
	r := NewRunner(db, nil)

	// Calling Stop multiple times concurrently and sequentially should be safe and not panic
	r.Stop()
	r.Stop()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Stop()
		}()
	}
	wg.Wait()
}
