package httpclient

import (
	"context"
	"errors"
	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/scope"
	"testing"
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
