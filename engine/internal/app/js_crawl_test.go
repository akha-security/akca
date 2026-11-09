package app

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/session"
	"github.com/akha-security/akca/engine/internal/storage"
)

type jsPhaseTransport func(*http.Request) (*http.Response, error)

func (f jsPhaseTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestJSAPIPhaseOnlyFetchesNewRequestsOnce(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/js-phase.db")
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewWithDB(noopWriter{}, db)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	const scanID = "js-phase"
	cfg := config.DefaultScanConfig()
	cfg.ScanID = scanID
	cfg.Targets = []string{"https://example.test/"}
	cfg.IncludeDomains = []string{"example.test"}
	cfg.GlobalRateLimit, cfg.PerHostRateLimit = 1000, 1000
	var requests atomic.Int32
	cfg.TestRoundTripper = jsPhaseTransport(func(r *http.Request) (*http.Response, error) {
		requests.Add(1)
		if r.URL.Path == "/redirect" {
			return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"/known"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
		}
		if r.URL.Path != "/new" {
			t.Errorf("unexpected repeated/expanded request: %s", r.URL)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/html"}}, Body: io.NopCloser(strings.NewReader(`<a href="/loop">loop</a><script src="/runtime.js"></script>`)), Request: r}, nil
	})
	e.session = session.NewScanSession(cfg)
	e.scope = scope.NewEngine(cfg)
	e.client, err = httpclient.New(cfg, e.scope, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct {
		path, source string
		status       int
	}{
		{"/known", "js_bundle", 200}, {"/missing", "js_bundle", 404}, {"/new", "link", 0}, {"/redirect", "js_bundle", 0},
	} {
		if err := db.SaveDiscoveredEndpoint(scanID, map[string]interface{}{
			"url": "https://example.test" + entry.path, "method": "GET", "source": entry.source,
			"request_template": map[string]interface{}{"response_status": entry.status},
		}); err != nil {
			t.Fatal(err)
		}
	}
	// A URL first seen as a link can later become a confirmed JS call site.
	if err := db.SaveDiscoveredEndpoint(scanID, map[string]interface{}{"url": "https://example.test/new", "method": "GET", "source": "js_analyzer"}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := e.runJSDiscoveredCrawlPhase(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if requests.Load() != 2 {
		t.Fatalf("JS phase sent %d requests, want only the two new APIs without repeating the known redirect target", requests.Load())
	}
}
