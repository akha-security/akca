package distributed

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/akha-security/akca/engine/internal/storage"
)

func testCoordinator(t *testing.T) (*storage.DB, *Coordinator) {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "akca.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(); err != nil {
		db.Close()
		t.Fatal(err)
	}
	return db, NewCoordinator(db, 150*time.Millisecond)
}

func TestJobsAreIdempotentCheckpointableAndOwnerLeased(t *testing.T) {
	db, coordinator := testCoordinator(t)
	defer db.Close()
	spec := Spec{
		IdempotencyKey: "scan-1:crawl:root", Type: JobCrawl, ScanID: "scan-1",
		Payload: json.RawMessage(`{"url":"https://example.test/"}`),
		Scope:   []string{"https://example.test/"}, RateLimitRPS: 10, MaxAttempts: 2,
	}
	first, err := coordinator.Enqueue(spec)
	if err != nil {
		t.Fatal(err)
	}
	second, err := coordinator.Enqueue(spec)
	if err != nil || first != second {
		t.Fatalf("idempotency failed: %q %q %v", first, second, err)
	}
	job, err := coordinator.Lease("worker-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Checkpoint(job.ID, "worker-b", map[string]int{"page": 2}); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("foreign worker changed checkpoint: %v", err)
	}
	if err := coordinator.Checkpoint(job.ID, "worker-a", map[string]int{"page": 2}); err != nil {
		t.Fatal(err)
	}
	current, err := coordinator.Get(job.ID)
	if err != nil || string(current.Checkpoint) != `{"page":2}` {
		t.Fatalf("checkpoint not persisted: %+v %v", current, err)
	}
}

func TestWorkerEnforcesScopeRateLimitAndCancellation(t *testing.T) {
	db, coordinator := testCoordinator(t)
	defer db.Close()
	jobID, err := coordinator.Enqueue(Spec{
		IdempotencyKey: "scan-2:inject:1", Type: JobInjection, ScanID: "scan-2",
		Payload: json.RawMessage(`{"url":"https://api.example.test/item"}`),
		Scope:   []string{"https://api.example.test/"}, RateLimitRPS: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	worker := Worker{
		ID: "worker-a", Coordinator: coordinator,
		Handlers: map[JobType]Handler{
			JobInjection: func(ctx context.Context, job Job, controls *Controls) error {
				if err := controls.AuthorizeURL("https://api.example.test/item"); err != nil {
					return err
				}
				if err := controls.AuthorizeURL("https://evil.test/"); !errors.Is(err, ErrOutOfScope) {
					return errors.New("out-of-scope URL was accepted")
				}
				if err := controls.Wait(ctx); err != nil {
					return err
				}
				return controls.Checkpoint(map[string]bool{"probe_sent": true})
			},
		},
	}
	if err := worker.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	completed, _ := coordinator.Get(jobID)
	if completed.Status != StatusCompleted {
		t.Fatalf("expected completed job, got %+v", completed)
	}

	cancelID, err := coordinator.Enqueue(Spec{
		IdempotencyKey: "scan-2:oast:1", Type: JobOASTWait, ScanID: "scan-2",
		Payload: json.RawMessage(`{}`), Scope: []string{"example.test"}, RateLimitRPS: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Cancel(cancelID); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Lease("worker-b"); !errors.Is(err, ErrNoJob) {
		t.Fatalf("canceled job was dispatched: %v", err)
	}
}

func TestExpiredLeaseIsRetriedAndEventuallyFails(t *testing.T) {
	db, coordinator := testCoordinator(t)
	defer db.Close()
	coordinator.now = func() time.Time { return time.Unix(1000, 0) }
	jobID, err := coordinator.Enqueue(Spec{
		IdempotencyKey: "scan-3:browser:1", Type: JobBrowser, ScanID: "scan-3",
		Payload: json.RawMessage(`{}`), Scope: []string{"example.test"}, RateLimitRPS: 1, MaxAttempts: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Lease("worker-a"); err != nil {
		t.Fatal(err)
	}
	coordinator.now = func() time.Time { return time.Unix(1001, 0) }
	job, err := coordinator.Lease("worker-b")
	if err != nil || job.ID != jobID || job.Attempts != 2 {
		t.Fatalf("expired lease was not retried: %+v %v", job, err)
	}
	if err := coordinator.Fail(job.ID, "worker-b", errors.New("fixture failure")); err != nil {
		t.Fatal(err)
	}
	failed, _ := coordinator.Get(job.ID)
	if failed.Status != StatusFailed {
		t.Fatalf("expected terminal failure: %+v", failed)
	}
}
