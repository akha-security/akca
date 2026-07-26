package jsanalyzer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/queue"
	"github.com/akha-security/akca/engine/internal/ratelimit"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/testfixtures"
)

func TestAnalyzerUsesCentralHTTPClient(t *testing.T) {
	jsBody := `fetch("/api/internal"); const t="` + testfixtures.GitHubShortToken() + `"; //# sourceMappingURL=leak.map`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app.js" {
			_, _ = w.Write([]byte(jsBody))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"127.0.0.1"}
	scopeEngine := scope.NewEngine(cfg)
	client, err := httpclient.New(cfg, scopeEngine, ratelimit.New(1000, 1000))
	if err != nil {
		t.Fatal(err)
	}

	db, err := storage.Open(t.TempDir() + "/js.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_ = db.Migrate()
	_ = db.EnsureScan("scan-js")

	var events []string
	q := queue.NewRequestQueue()
	a := New("scan-js", client, scopeEngine, db, q, func(eventType, message string, payload map[string]interface{}) error {
		events = append(events, eventType)
		return nil
	})

	result, err := a.DownloadAndAnalyze(context.Background(), srv.URL+"/app.js")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Endpoints) == 0 {
		t.Fatal("expected extracted endpoints")
	}
	if len(result.Secrets) == 0 {
		t.Fatal("expected secret detection")
	}
	if len(result.SourceMaps) == 0 {
		t.Fatal("expected source map detection")
	}

	foundSecretEvent := false
	for _, e := range events {
		if e == "js_secret_detected" || e == "source_map_exposed" {
			foundSecretEvent = true
		}
	}
	if !foundSecretEvent {
		t.Fatalf("expected secret/sourcemap events, got %v", events)
	}
}
