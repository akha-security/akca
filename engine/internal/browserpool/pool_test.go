package browserpool

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/akha-security/akca/engine/internal/storage"
)

func TestPoolEnqueueWorker(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/akca.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	p := NewPool(db, 2)
	p.SetPageFetcher(func(_ context.Context, _ string) (string, error) {
		return "<html>rendered</html>", nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Start(ctx)
	p.Enqueue(Task{ID: "t1", Type: TaskSPACrawl, URL: "https://example.com"})
	deadline := time.Now().Add(2 * time.Second)
	for {
		rows, listErr := db.ListBrowserWorkers()
		if listErr != nil {
			t.Fatal(listErr)
		}
		completed := false
		for _, row := range rows {
			var worker Worker
			if json.Unmarshal([]byte(row.HealthJSON), &worker) == nil && worker.Completed > 0 {
				completed = true
			}
		}
		if completed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("real page fetch task was not completed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	p.Stop()
}

func TestPoolFailsUnsupportedWorkInsteadOfSimulatingSuccess(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/unsupported.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	p := NewPool(db, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Start(ctx)
	p.Enqueue(Task{ID: "login", Type: TaskLoginCapture, URL: "https://example.com/login"})
	deadline := time.Now().Add(2 * time.Second)
	for {
		rows, listErr := db.ListBrowserWorkers()
		if listErr != nil {
			t.Fatal(listErr)
		}
		for _, row := range rows {
			var worker Worker
			if json.Unmarshal([]byte(row.HealthJSON), &worker) == nil && worker.Failed > 0 {
				if worker.Completed != 0 || worker.LastError == "" {
					t.Fatalf("unsupported task was not reported honestly: %+v", worker)
				}
				p.Stop()
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("unsupported task was not marked failed")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
