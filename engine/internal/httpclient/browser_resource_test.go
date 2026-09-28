package httpclient

import (
	"context"
	"errors"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/scope"
)

func TestBrowserDependencyDoesNotExpandActiveScope(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"app.test"}
	cfg.BrowserResourceDomains = []string{"cdn.test"}
	cfg.RequestBudget = 1
	sc := scope.NewEngine(cfg)
	c, err := New(cfg, sc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(c.ReserveExternal(context.Background(), "https://cdn.test/a.js", "browser"), ErrOutsideScope) {
		t.Fatal("CDN entered active scope")
	}
	if err = c.ReserveBrowserResource(context.Background(), "https://cdn.test/a.js", "browser_resource"); err != nil {
		t.Fatal(err)
	}
	if sc.IsInScope("https://cdn.test/") {
		t.Fatal("passive resource expanded scope")
	}
	if err = c.ReserveBrowserResource(context.Background(), "https://cdn.test/b.js", "browser_resource"); err == nil {
		t.Fatal("dependency bypassed global request budget")
	}
	if !errors.Is(c.ReserveBrowserResource(context.Background(), "https://cdn.test.evil/a.js", "browser_resource"), ErrOutsideScope) {
		t.Fatal("suffix confusion")
	}
}

func TestLearnedBrowserDependenciesRemainPassiveAndExact(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"app.test"}
	cfg.RequestBudget = 0
	sc := scope.NewEngine(cfg)
	c, err := New(cfg, sc, nil)
	if err != nil {
		t.Fatal(err)
	}
	added := c.AdmitBrowserResourceDomains([]string{"cdn.example.test", "CDN.EXAMPLE.TEST", ""})
	if len(added) != 1 || added[0] != "cdn.example.test" {
		t.Fatalf("learned dependencies=%v", added)
	}
	if err := c.ReserveBrowserResource(context.Background(), "https://cdn.example.test/app.js", "browser_resource"); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(c.ReserveExternal(context.Background(), "https://cdn.example.test/api", "browser"), ErrOutsideScope) {
		t.Fatal("learned passive dependency expanded active scan scope")
	}
	if !errors.Is(c.ReserveBrowserResource(context.Background(), "https://cdn.example.test.evil/app.js", "browser_resource"), ErrOutsideScope) {
		t.Fatal("learned dependency allowed suffix confusion")
	}
}

func TestLearnedBrowserDependenciesRejectLocalNetworkTargets(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"app.test"}
	sc := scope.NewEngine(cfg)
	c, err := New(cfg, sc, nil)
	if err != nil {
		t.Fatal(err)
	}
	added := c.AdmitBrowserResourceDomains([]string{
		"127.0.0.1", "169.254.169.254", "10.0.0.5", "localhost", "router.local", "api.internal", "cdn.example.test",
	})
	if len(added) != 1 || added[0] != "cdn.example.test" {
		t.Fatalf("unsafe learned dependency host was admitted: %v", added)
	}
}
