package httpclient

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/scope"
)

func limitedRequestContext(limit int64) (context.Context, *atomic.Int64) {
	used := new(atomic.Int64)
	return WithRequestBudget(context.Background(), func() error {
		for {
			n := used.Load()
			if n >= limit {
				return fmt.Errorf("request budget exhausted for test allocation")
			}
			if used.CompareAndSwap(n, n+1) {
				return nil
			}
		}
	}), used
}

func TestAllocationIncludesRedirectHops(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/next", 302)
		case "/next":
			http.Redirect(w, r, "/last", 302)
		default:
			w.Write([]byte("ok"))
		}
	}))
	defer srv.Close()
	cfg := config.DefaultScanConfig()
	cfg.Targets = []string{srv.URL}
	cfg.FollowRedirects = true
	c, err := New(cfg, scope.NewEngine(cfg), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, used := limitedRequestContext(2)
	_, err = c.Do(ctx, "GET", srv.URL, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "request budget exhausted") {
		t.Fatalf("redirect escaped allocation: %v", err)
	}
	if hits.Load() != 2 || used.Load() != 2 || c.NetworkAttempts() != 2 {
		t.Fatalf("hits=%d reserved=%d wire=%d", hits.Load(), used.Load(), c.NetworkAttempts())
	}
}

func TestAllocationSharedAcrossHTTPAndExternalReservations(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.Write([]byte("ok")) }))
	defer srv.Close()
	cfg := config.DefaultScanConfig()
	cfg.Targets = []string{srv.URL}
	cfg.GlobalRateLimit = 1000
	cfg.PerHostRateLimit = 1000
	c, err := New(cfg, scope.NewEngine(cfg), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, used := limitedRequestContext(10)
	var wg sync.WaitGroup
	var external atomic.Int64
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				_, _ = c.Do(ctx, "GET", srv.URL, nil, nil)
			} else if c.ReserveExternal(ctx, srv.URL, "test") == nil {
				external.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if hits.Load()+external.Load() != 10 || used.Load() != 10 || c.NetworkAttempts() != 10 {
		t.Fatalf("hits=%d external=%d used=%d wire=%d", hits.Load(), external.Load(), used.Load(), c.NetworkAttempts())
	}
}
