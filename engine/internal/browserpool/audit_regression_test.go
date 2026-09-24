package browserpool

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
)

func TestPassiveResourcePolicyStripsCredentials(t *testing.T) {
	for _, kind := range []string{"Document", "XHR", "Fetch", "WebSocket"} {
		if passiveBrowserResource(kind, "GET") {
			t.Fatalf("active resource allowed: %s", kind)
		}
	}
	if passiveBrowserResource("Script", "POST") || !passiveBrowserResource("Script", "GET") {
		t.Fatal("invalid method policy")
	}
	headers := passiveResourceHeaders(map[string]string{"Cookie": "secret", "Authorization": "secret", "X-Custom-Key": "secret", "Referer": "https://app/?token=secret", "Accept": "*/*"})
	if len(headers) != 1 || headers[0]["value"] != "*/*" {
		t.Fatalf("credential leakage: %v", headers)
	}
}

func TestBrowserLoadsAllowedCDNWithoutCredentials(t *testing.T) {
	if testing.Short() {
		t.Skip("real browser integration")
	}
	requests := make(chan http.Header, 4)
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Header.Clone()
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`document.querySelector('#result').textContent='cdn-loaded';`))
	}))
	defer cdn.Close()
	cdnURL := strings.Replace(cdn.URL, "127.0.0.1", "localhost", 1)
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<div id="result">waiting</div><script src="` + cdnURL + `/app.js"></script>`))
	}))
	defer app.Close()
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"127.0.0.1"}
	cfg.BrowserResourceDomains = []string{"localhost"}
	client, err := httpclient.New(cfg, scope.NewEngine(cfg), nil)
	if err != nil {
		t.Fatal(err)
	}
	b := NewCrawlerBrowserWithSession(nil, nil, "", false, map[string]string{"Authorization": "Bearer private-token", "X-Private-Key": "private-key"}, nil)
	defer b.Close()
	if !b.renderer.Available() {
		t.Skip("Chromium unavailable")
	}
	t.Setenv("AKCA_BROWSER_DISABLE_SANDBOX", "1")
	b.SetRequestGuard(client.ReserveExternal)
	b.SetResourceGuard(client.ReserveBrowserResource)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	snapshot, err := b.FetchInstrumented(ctx, app.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(snapshot.DOM, "cdn-loaded") {
		t.Fatalf("allowed CDN did not execute: %s", snapshot.DOM)
	}
	select {
	case h := <-requests:
		if h.Get("Authorization") != "" || h.Get("X-Private-Key") != "" || h.Get("Cookie") != "" {
			t.Fatalf("credential-bearing CDN request: %v", h)
		}
	default:
		t.Fatal("CDN was not requested")
	}
}

func TestCrawlerBrowserRetainsSessionAndDiscoversTab(t *testing.T) {
	if testing.Short() {
		t.Skip("real browser integration")
	}
	b := NewCrawlerBrowser(nil, nil)
	defer b.Close()
	if !b.renderer.Available() {
		t.Skip("Chromium unavailable")
	}
	t.Setenv("AKCA_BROWSER_DISABLE_SANDBOX", "1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/first" {
			http.SetCookie(w, &http.Cookie{Name: "retained", Value: "yes", Path: "/"})
			_, _ = w.Write([]byte(`<script>localStorage.setItem('tenant','retained'); sessionStorage.setItem('step','retained')</script>first`))
			return
		}
		cookie, err := r.Cookie("retained")
		if err != nil || cookie.Value != "yes" {
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte(`<div id="result"></div><button type="button" role="tab" aria-controls="result" onclick="document.querySelector('#result').innerHTML='<a href=/tab-child>child</a>'">Tab</button>`))
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if _, err := b.FetchInstrumented(ctx, srv.URL+"/first"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := b.FetchInstrumented(ctx, srv.URL+"/second")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.DocumentStatus != 200 || snapshot.LocalStorage["tenant"] != "retained" || snapshot.SessionStorage["step"] != "retained" || !strings.Contains(snapshot.DOM, `href="/tab-child"`) {
		t.Fatalf("browser lost state or tab discovery: status=%d local=%v session=%v dom=%s", snapshot.DocumentStatus, snapshot.LocalStorage, snapshot.SessionStorage, snapshot.DOM)
	}
}
