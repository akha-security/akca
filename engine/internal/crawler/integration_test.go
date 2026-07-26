package crawler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/ratelimit"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
)

func TestCrawlerScopeBlockingAndPersistence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<html><a href="/api/data">api</a><a href="https://offscope.com/x">bad</a></html>`))
		case "/api/data":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		case "/robots.txt":
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /private\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"127.0.0.1"}
	cfg.MaxPages = 10
	cfg.MaxDepth = 2
	cfg.RequestBudget = 20

	scopeEngine := scope.NewEngine(cfg)
	client, err := httpclient.New(cfg, scopeEngine, ratelimit.New(1000, 1000))
	if err != nil {
		t.Fatal(err)
	}

	db, err := storage.Open(t.TempDir() + "/crawl.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}

	var events []string
	c := New("scan-crawl", cfg, client, scopeEngine, db, func(eventType, message string, payload map[string]interface{}) error {
		events = append(events, eventType)
		return nil
	})

	if err := c.Crawl(context.Background(), []string{srv.URL}); err != nil {
		t.Fatal(err)
	}

	count, err := db.CountEndpoints("scan-crawl")
	if err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatal("expected persisted endpoints")
	}

	foundCrawlerFinished := false
	for _, e := range events {
		if e == "crawler_finished" {
			foundCrawlerFinished = true
		}
	}
	if !foundCrawlerFinished {
		t.Fatalf("events=%v", events)
	}
}

func TestSeedIngestionAPI(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"example.com", "api.example.com"}
	scopeEngine := scope.NewEngine(cfg)

	db, err := storage.Open(t.TempDir() + "/seed.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_ = db.Migrate()

	c := New("scan-seed", cfg, nil, scopeEngine, db, func(string, string, map[string]interface{}) error { return nil })
	added := c.IngestSeeds([]string{
		"https://api.example.com",
		"https://offscope.org",
		"https://api.example.com",
	})
	if added != 1 {
		t.Fatalf("expected 1 seed, got %d", added)
	}
}

func TestLargeEndpointPersistence(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/large.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_ = db.Migrate()

	for i := 0; i < 200; i++ {
		ep := DiscoveredEndpoint{
			URL:           "https://example.com/path/" + string(rune('a'+i%26)),
			Method:        "GET",
			NormalizedURL: "https://example.com/path/" + string(rune('a'+i%26)),
			Source:        SourceLink,
			Confidence:    0.8,
			WhyDiscovered: "bulk test",
		}
		if err := db.SaveDiscoveredEndpoint("scan-large", ep); err != nil {
			t.Fatal(err)
		}
	}
	count, err := db.CountEndpoints("scan-large")
	if err != nil {
		t.Fatal(err)
	}
	if count < 26 {
		t.Fatalf("expected deduped bulk inserts, count=%d", count)
	}
}
