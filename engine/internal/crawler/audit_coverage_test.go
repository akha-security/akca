package crawler

import (
	"context"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
)

func auditCrawler(t *testing.T, cfg config.ScanConfig, responses map[string]httpclient.ResponseRecord) *Crawler {
	t.Helper()
	db, err := storage.Open(t.TempDir() + "/audit.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err = db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err = db.EnsureScan("audit"); err != nil {
		t.Fatal(err)
	}
	return New("audit", cfg, &discoveryClient{responses: responses, visited: map[string]bool{}}, scope.NewEngine(cfg), db, nil)
}

func TestRobotsSuccessDoesNotHideRejectedApplication(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"example.test"}
	cfg.EnableHeadlessCrawler = false
	c := auditCrawler(t, cfg, map[string]httpclient.ResponseRecord{
		"https://example.test/":           {StatusCode: 403, Body: "denied"},
		"https://example.test/robots.txt": {StatusCode: 200, Body: "User-agent: *"},
	})
	if err := c.Crawl(context.Background(), []string{"https://example.test/"}); err == nil || !strings.Contains(err.Error(), "no usable page content") {
		t.Fatalf("blocked app incorrectly successful: %v", err)
	}
}

func TestBudgetCutPreservesDiscoveredURLsAndReturnsIncomplete(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"example.test"}
	cfg.MaxPages = 1
	cfg.MaxConcurrency = 4
	c := auditCrawler(t, cfg, map[string]httpclient.ResponseRecord{"https://example.test/": {StatusCode: 200, Body: `<a href="/child">child</a>`}})
	if err := c.Crawl(context.Background(), []string{"https://example.test/"}); err == nil {
		t.Fatal("budget cut reported complete")
	}
	_, requests, _ := c.Stats()
	if requests != 1 {
		t.Fatalf("page reservation overshot: %d", requests)
	}
	var count int
	if err := c.db.Conn().QueryRow("SELECT COUNT(*) FROM endpoints WHERE scan_id=? AND url=?", "audit", "https://example.test/child").Scan(&count); err != nil || count != 1 {
		t.Fatalf("unvisited discovery lost: count=%d err=%v", count, err)
	}
}

func TestDepthExcludedDiscoveryCanBeUpgraded(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"example.test"}
	c := auditCrawler(t, cfg, nil)
	budget := Budget{MaxDepth: 1}
	c.enqueueCandidate("https://example.test/deep", "GET", 2, SourceLink, 1, "deep link", budget, nil, "")
	c.enqueueCandidate("https://example.test/deep", "GET", 1, SourceLink, 1, "shallow link", budget, nil, "")
	found := false
	for {
		item, ok := c.q.Dequeue()
		if !ok {
			break
		}
		if item.URL == "https://example.test/deep" {
			found = true
		}
	}
	if !found {
		t.Fatal("excluded discovery poisoned subsequent shallower route")
	}
}
