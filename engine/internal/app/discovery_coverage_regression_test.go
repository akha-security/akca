package app

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/events"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/session"
	"github.com/akha-security/akca/engine/internal/storage"
)

func TestInitialDiscoveryKeepsHiddenInputsOnQuerylessHandlers(t *testing.T) {
	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultScanConfig()
	cfg.ScanID = "initial-hidden-inputs"
	cfg.Targets = []string{"https://example.test"}
	cfg.IncludeDomains = []string{"example.test"}
	cfg.GlobalRateLimit, cfg.PerHostRateLimit = 10000, 10000
	cfg.TestRoundTripper = php2ShellTransportFunc(func(req *http.Request) (*http.Response, error) {
		code, body := 200, "<html><body>ordinary application response</body></html>"
		if req.URL.Query().Get("page") != "" || req.URL.Query().Get("language") != "" {
			code, body = 202, "<html><body>Selected page has different results</body></html>"
		}
		return &http.Response{StatusCode: code, Header: http.Header{"Content-Type": []string{"text/html"}}, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
	})
	if err := db.EnsureScan(cfg.ScanID); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/index.php", "/search"} {
		if err := db.SaveDiscoveredEndpoint(cfg.ScanID, map[string]interface{}{"url": cfg.Targets[0] + path, "method": "GET", "source": "crawler"}); err != nil {
			t.Fatal(err)
		}
	}
	sc := scope.NewEngine(cfg)
	client, err := httpclient.New(cfg, sc, nil)
	if err != nil {
		t.Fatal(err)
	}
	batcher := events.NewBatcher(noopWriter{}, 100, time.Hour)
	defer batcher.Close()
	e := &Engine{db: db, session: session.NewScanSession(cfg), client: client, scope: sc, batcher: batcher}
	if err := e.runParameterDiscoveryPhase(context.Background()); err != nil {
		t.Fatal(err)
	}
	runner := e.vulnModuleRunner()
	defer runner.Close()
	targets, err := runner.LoadTargetsWithEndpointsFromDB(0)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/index.php", "/search"} {
		for _, parameter := range []string{"page", "language"} {
			found := false
			for _, target := range targets {
				if target.EndpointURL == cfg.Targets[0]+path && target.Parameter == parameter && target.Location == "query" {
					found = true
				}
			}
			if !found {
				t.Errorf("hidden %s parameter on %s never reached initial vulnerability targets", parameter, path)
			}
		}
	}
}

func TestInitialCrawlUsesConfiguredCoverageBeforeModuleScanning(t *testing.T) {
	db, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultScanConfig()
	cfg.ScanID = "full-initial-crawl"
	cfg.Targets = []string{"https://example.test/"}
	cfg.IncludeDomains = []string{"example.test"}
	cfg.MaxPages, cfg.CrawlerRequestBudget = 128, 256
	cfg.EnableHeadlessCrawler = false
	cfg.EnableJSAnalysis = false
	cfg.GlobalRateLimit, cfg.PerHostRateLimit = 10000, 10000
	var mu sync.Mutex
	seen := map[string]bool{}
	cfg.TestRoundTripper = php2ShellTransportFunc(func(req *http.Request) (*http.Response, error) {
		code, body := 404, "not found"
		if req.URL.Path == "/" {
			code, body = 200, "<html><body>"
			for i := 0; i < 40; i++ {
				body += fmt.Sprintf(`<a href="/page-%d">Page</a>`, i)
			}
			body += "</body></html>"
		} else if strings.HasPrefix(req.URL.Path, "/page-") {
			code, body = 200, "<html><body>Application page</body></html>"
			mu.Lock()
			seen[req.URL.Path] = true
			mu.Unlock()
		}
		return &http.Response{StatusCode: code, Header: http.Header{"Content-Type": []string{"text/html"}}, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
	})
	if err := db.EnsureScan(cfg.ScanID); err != nil {
		t.Fatal(err)
	}
	sc := scope.NewEngine(cfg)
	client, err := httpclient.New(cfg, sc, nil)
	if err != nil {
		t.Fatal(err)
	}
	batcher := events.NewBatcher(noopWriter{}, 100, time.Hour)
	defer batcher.Close()
	e := &Engine{db: db, session: session.NewScanSession(cfg), client: client, scope: sc, batcher: batcher}
	if err := e.runCrawlerStage(context.Background(), cfg.Targets, true); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 40 {
		t.Fatalf("initial crawl visited %d of 40 application pages before modules", len(seen))
	}
}
