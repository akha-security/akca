package httpclient

import (
	"context"
	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/scope"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

func TestSharedBudgetAcrossHTTPAndExternalWorkers(t *testing.T) {
	var wire atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { wire.Add(1); w.Write([]byte("ok")) }))
	defer server.Close()
	cfg := config.DefaultScanConfig()
	cfg.Targets = []string{server.URL}
	cfg.RequestBudget = 12
	c, err := New(cfg, scope.NewEngine(cfg), nil)
	if err != nil {
		t.Fatal(err)
	}
	var external atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				_, _ = c.Do(context.Background(), "GET", server.URL, nil, nil)
			} else if c.ReserveExternal(context.Background(), server.URL, "browser") == nil {
				external.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if got := wire.Load() + external.Load(); got != 12 {
		t.Fatalf("budget consumed %d, wanted 12", got)
	}
	if c.NetworkAttempts() != 12 {
		t.Fatalf("denied requests inflated counter: %d", c.NetworkAttempts())
	}
	if err := c.ReserveExternal(context.Background(), "https://outside.invalid", "raw_tcp"); err == nil {
		t.Fatal("outside scope was allowed")
	}
}
