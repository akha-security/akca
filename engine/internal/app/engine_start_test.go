package app

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/storage"
)

func TestEnsureOASTRenewsRegistrationForEveryScan(t *testing.T) {
	var registrations atomic.Int32
	var deregistrations atomic.Int32
	oastServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/register":
			registrations.Add(1)
			_, _ = w.Write([]byte(`{"message":"registration successful"}`))
		case "/deregister":
			deregistrations.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer oastServer.Close()

	storage.SetDataDirOverride(t.TempDir())
	engine, err := New(noopWriter{})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	cfg := config.DefaultScanConfig()
	cfg.EnableOAST = true
	cfg.OASTServerURL = oastServer.URL
	cfg.OASTPollInterval = time.Hour
	cfg.ScanID = "oast-first-scan"
	if err := engine.ensureOAST(cfg); err != nil {
		t.Fatal(err)
	}
	first := engine.oast
	first.SetScanID(cfg.ScanID)

	cfg.ScanID = "oast-second-scan"
	if err := engine.ensureOAST(cfg); err != nil {
		t.Fatal(err)
	}
	second := engine.oast
	if first == second {
		t.Fatal("a later scan reused the previous OAST listener")
	}
	if got := registrations.Load(); got != 2 {
		t.Fatalf("registrations = %d, want 2", got)
	}
	if got := deregistrations.Load(); got != 1 {
		t.Fatalf("deregistrations = %d, want 1 before engine shutdown", got)
	}
}

func TestStartScanDoesNotDeadlockWhenOASTRegistrationFails(t *testing.T) {
	oastServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer oastServer.Close()

	storage.SetDataDirOverride(t.TempDir())
	engine, err := New(noopWriter{})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	cfg := config.DefaultScanConfig()
	cfg.ScanID = "oast-startup-failure"
	cfg.Targets = []string{"http://127.0.0.1:1"}
	cfg.OASTServerURL = oastServer.URL
	cfg.EnableBrowserWorkerPool = false
	cfg.EnableRuntimeSensor = false
	cfg.EnableHeadlessCrawler = false
	cfg.EnableJSAnalysis = false
	cfg.EnableFuzzing = false
	cfg.Enable403BypassChecks = false
	cfg.SkipAutoReport = true

	started := make(chan error, 1)
	go func() { started <- engine.StartScan(cfg) }()

	select {
	case err := <-started:
		if err != nil {
			t.Fatalf("StartScan returned an error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("StartScan deadlocked after OAST registration failure")
	}

	if err := engine.StopScan(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := engine.WaitScanDone(ctx); err != nil && err != context.Canceled {
		t.Fatalf("scan did not stop: %v", err)
	}
}

func TestNormalScanCrawlsLinksBeforeFingerprintRequests(t *testing.T) {
	storage.SetDataDirOverride(t.TempDir())
	engine, err := New(noopWriter{})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	cfg := config.DefaultScanConfig()
	cfg.ScanID = "crawl-before-fingerprint"
	cfg.Targets = []string{"https://example.test/"}
	cfg.IncludeDomains = []string{"example.test"}
	cfg.EnableOAST = false
	cfg.EnableWAFDetection = false
	cfg.EnableJSAnalysis = false
	cfg.EnableHeadlessCrawler = false
	cfg.EnableBrowserWorkerPool = false
	cfg.EnableRuntimeSensor = false
	cfg.EnableFuzzing = false
	cfg.Enable403BypassChecks = false
	cfg.SkipAutoReport = true
	cfg.MaxPages = 2
	cfg.CrawlerRequestBudget = 2
	cfg.GlobalRateLimit, cfg.PerHostRateLimit = 10000, 10000
	requests := make(chan string, 100)
	cfg.TestRoundTripper = php2ShellTransportFunc(func(req *http.Request) (*http.Response, error) {
		requests <- req.URL.Path
		body := "<html>child</html>"
		if req.URL.Path == "/" {
			body = `<html><a href="/child">child</a></html>`
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/html"}}, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
	})
	if err := engine.StartScan(cfg); err != nil {
		t.Fatal(err)
	}
	childSeen := false
	deadline := time.After(5 * time.Second)
	for {
		select {
		case path := <-requests:
			if path == "/child" {
				childSeen = true
			} else if path == "/" && childSeen {
				if err := engine.StopScan(); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = engine.WaitScanDone(ctx)
				return
			}
		case <-deadline:
			t.Fatalf("crawler did not visit child before fingerprint request (child_seen=%v)", childSeen)
		}
	}
}
