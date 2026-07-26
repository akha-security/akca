package scanapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/distributed"
	"github.com/akha-security/akca/engine/internal/report"
	"github.com/akha-security/akca/engine/internal/storage"
)

type fakeEngine struct {
	started chan struct{}
	done    chan struct{}
}

func (f *fakeEngine) StartScan(config.ScanConfig) error {
	close(f.started)
	return nil
}
func (f *fakeEngine) StopScan() error {
	select {
	case <-f.done:
	default:
		close(f.done)
	}
	return nil
}
func (f *fakeEngine) WaitScanDone(context.Context) error {
	<-f.done
	return nil
}
func (f *fakeEngine) GenerateReport(report.Options) ([]byte, error) {
	return []byte(`{"findings":[]}`), nil
}

type fakeJobEngine struct {
	*fakeEngine
	coordinator *distributed.Coordinator
}

func (f *fakeJobEngine) EnqueueDistributedJob(spec distributed.Spec) (string, error) {
	return f.coordinator.Enqueue(spec)
}
func (f *fakeJobEngine) LeaseDistributedJob(worker string) (distributed.Job, error) {
	return f.coordinator.Lease(worker)
}
func (f *fakeJobEngine) GetDistributedJob(id string) (distributed.Job, error) {
	return f.coordinator.Get(id)
}
func (f *fakeJobEngine) HeartbeatDistributedJob(id, worker string) error {
	return f.coordinator.Heartbeat(id, worker)
}
func (f *fakeJobEngine) CheckpointDistributedJob(id, worker string, value json.RawMessage) error {
	return f.coordinator.Checkpoint(id, worker, value)
}
func (f *fakeJobEngine) CompleteDistributedJob(id, worker string) error {
	return f.coordinator.Complete(id, worker)
}
func (f *fakeJobEngine) FailDistributedJob(id, worker, message string) error {
	return f.coordinator.Fail(id, worker, io.ErrUnexpectedEOF)
}
func (f *fakeJobEngine) CancelDistributedJob(id string) error {
	return f.coordinator.Cancel(id)
}

func TestAPIRequiresTokenAndStartsDefaultedScan(t *testing.T) {
	engine := &fakeEngine{started: make(chan struct{}), done: make(chan struct{})}
	server, err := New(engine, "this-is-a-long-test-token-123")
	if err != nil {
		t.Fatal(err)
	}
	unauthorized := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, unauthorized)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected token rejection, got %d", response.Code)
	}
	body := strings.NewReader(`{"targets":["https://example.test"],"scan_id":"api-test"}`)
	request := httptest.NewRequest(http.MethodPost, "/v1/scans", body)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer this-is-a-long-test-token-123")
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		raw, _ := io.ReadAll(response.Body)
		t.Fatalf("expected accepted scan, got %d: %s", response.Code, raw)
	}
	engine.StopScan()
}

func TestReportIsRedactedAndAttachmentSafe(t *testing.T) {
	engine := &fakeEngine{started: make(chan struct{}), done: make(chan struct{})}
	server, _ := New(engine, "this-is-a-long-test-token-123")
	request := httptest.NewRequest(http.MethodGet, "/v1/reports?scan_id=../../bad&format=sarif", nil)
	request.Header.Set("Authorization", "Bearer this-is-a-long-test-token-123")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK ||
		strings.Contains(response.Header().Get("Content-Disposition"), "..") {
		t.Fatalf("unsafe report response: %d %s", response.Code, response.Header())
	}
}

func TestDistributedWorkerProtocol(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "jobs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	engine := &fakeJobEngine{
		fakeEngine:  &fakeEngine{started: make(chan struct{}), done: make(chan struct{})},
		coordinator: distributed.NewCoordinator(db, time.Second),
	}
	server, _ := New(engine, "this-is-a-long-test-token-123")
	call := func(method, path, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer this-is-a-long-test-token-123")
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response
	}
	enqueued := call(http.MethodPost, "/v1/jobs", `{
	  "idempotency_key":"scan:crawl:root","job_type":"crawl","scan_id":"scan",
	  "payload":{"url":"https://example.test"},"scope":["example.test"],"rate_limit_rps":5
	}`)
	if enqueued.Code != http.StatusAccepted {
		t.Fatalf("enqueue failed: %d %s", enqueued.Code, enqueued.Body.String())
	}
	var idBody map[string]string
	_ = json.Unmarshal(enqueued.Body.Bytes(), &idBody)
	leased := call(http.MethodPost, "/v1/jobs/lease", `{"worker_id":"remote-1"}`)
	if leased.Code != http.StatusOK || !strings.Contains(leased.Body.String(), idBody["id"]) {
		t.Fatalf("lease failed: %d %s", leased.Code, leased.Body.String())
	}
	checkpointed := call(http.MethodPost, "/v1/jobs/"+idBody["id"]+"/checkpoint",
		`{"worker_id":"remote-1","checkpoint":{"page":3}}`)
	if checkpointed.Code != http.StatusOK {
		t.Fatalf("checkpoint failed: %d %s", checkpointed.Code, checkpointed.Body.String())
	}
	completed := call(http.MethodPost, "/v1/jobs/"+idBody["id"]+"/complete",
		`{"worker_id":"remote-1"}`)
	if completed.Code != http.StatusOK {
		t.Fatalf("complete failed: %d %s", completed.Code, completed.Body.String())
	}
}
