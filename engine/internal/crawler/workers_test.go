package crawler

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
)

func TestCrawlerWorkersHonorRuntimeWAFConcurrencyCap(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.ScanIntensity = "fast"
	cfg.MaxConcurrency = 8
	cfg.Targets = []string{"https://example.test/"}
	if got := crawlerWorkerCount(cfg); got != 4 {
		t.Fatalf("single-host crawler workers=%d, want 4", got)
	}
	cfg.Targets = []string{"https://example.test/", "https://second.test/"}
	if got := crawlerWorkerCount(cfg); got != 8 {
		t.Fatalf("two-host crawler workers=%d, want runtime WAF cap 8", got)
	}
	cfg.PerHostConcurrency = 1
	if got := crawlerWorkerCount(cfg); got != 2 {
		t.Fatalf("crawler ignored stricter per-host limit: %d", got)
	}
}
