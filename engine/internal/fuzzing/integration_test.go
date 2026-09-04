package fuzzing

import (
	"context"
	"net/url"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
)

type mockDoer struct {
	statusByPath map[string]int
	contentType  map[string]string
}

func (m *mockDoer) Do(_ context.Context, _, rawURL string, _ []byte, _ map[string]string) (httpclient.RequestResponse, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return httpclient.RequestResponse{}, err
	}
	status := 404
	if s, ok := m.statusByPath[u.Path]; ok {
		status = s
	}
	ct := m.contentType[u.Path]
	body := ""
	if status == 200 && u.Path == "/backup.zip" {
		body = "PK"
	}
	return httpclient.RequestResponse{
		Request: httpclient.RequestRecord{Method: "GET", URL: rawURL},
		Response: httpclient.ResponseRecord{
			StatusCode: status,
			Headers:    map[string]string{"Content-Type": ct},
			Body:       body,
		},
	}, nil
}

func TestFuzzEngineWorkerPool(t *testing.T) {
	cfg := config.DefaultScanConfig()
	scopeEngine := scope.NewEngine(cfg)
	client := &mockDoer{
		statusByPath: map[string]int{
			"/backup.zip": 200,
			"/admin":      403,
		},
		contentType: map[string]string{
			"/backup.zip": "application/zip",
		},
	}

	db, err := storage.Open(t.TempDir() + "/fuzz.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_ = db.Migrate()

	var batches int
	var summary map[string]interface{}
	fe := NewEngine("scan-f", client, scopeEngine, db, func(eventType, message string, payload map[string]interface{}) error {
		if eventType == "fuzz_result_batch" {
			batches++
		}
		if eventType == "fuzzing_discovery_summary" {
			summary = payload
		}
		return nil
	}, 4)

	tasks := []FuzzTask{
		{URL: "http://127.0.0.1/backup.zip", Method: "GET", Category: CategoryArchive, Path: "/backup.zip"},
		{URL: "http://127.0.0.1/admin", Method: "GET", Category: CategoryAdmin, Path: "/admin"},
		{URL: "http://127.0.0.1/robots.txt", Method: "GET", Category: CategoryGeneral, Path: "/robots.txt"},
	}

	if err := fe.RunTasks(context.Background(), tasks); err != nil {
		t.Fatal(err)
	}
	if batches == 0 {
		t.Fatal("expected aggregated fuzz batches")
	}
	if fe.Queue403().Metrics().TotalEnqueued == 0 {
		t.Fatal("expected 403 queue entries")
	}
	count, err := db.CountEndpoints("scan-f")
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("expected two promoted fuzz endpoints, got %d", count)
	}
	if summary == nil || summary["live"] == nil {
		t.Fatalf("expected fuzzing discovery summary, got %+v", summary)
	}
}
