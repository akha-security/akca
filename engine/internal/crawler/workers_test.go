package crawler

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
)

func TestCrawlerWorkersHonorRuntimeWAFConcurrencyCap(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.ScanIntensity = "fast"
	cfg.MaxConcurrency = 8
	if got := crawlerWorkerCount(cfg); got != 8 {
		t.Fatalf("crawler workers=%d, want runtime WAF cap 8", got)
	}
}
