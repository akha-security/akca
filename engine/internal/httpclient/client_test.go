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
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/ratelimit"
	"github.com/akha-security/akca/engine/internal/scope"
)

func TestConcurrentAuthProfilesDoNotLeakAcrossRequests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Header.Get("Authorization") + "|" + r.Header.Get("Cookie")))
	}))
	defer srv.Close()

	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{srv.URL}
	client, err := New(cfg, scope.NewEngine(cfg), ratelimit.New(1000, 1000))
	if err != nil {
		t.Fatal(err)
	}
	profiles := []config.AuthProfile{
		{Headers: map[string]string{"Authorization": "Bearer role-a"}, Cookies: map[string]string{"sid": "a"}},
		{Headers: map[string]string{"Authorization": "Bearer role-b"}, Cookies: map[string]string{"sid": "b"}},
	}
	var wg sync.WaitGroup
	errs := make(chan error, 100)
	for i := 0; i < 100; i++ {
		profile := profiles[i%len(profiles)]
		want := profile.Headers["Authorization"] + "|sid=" + profile.Cookies["sid"]
		wg.Add(1)
		go func() {
			defer wg.Done()
			rr, requestErr := client.DoWithAuthProfile(context.Background(), http.MethodGet, srv.URL, nil, nil, profile)
			if requestErr != nil {
				errs <- requestErr
				return
			}
			if rr.Response.Body != want {
				errs <- fmt.Errorf("auth profile leaked: got %q want %q", rr.Response.Body, want)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestRetryAfterDurationSupportsHTTPDate(t *testing.T) {
	when := time.Now().Add(2 * time.Minute).UTC().Format(http.TimeFormat)
	wait := retryAfterDuration(when, time.Second)
	if wait < 110*time.Second || wait > 2*time.Minute {
		t.Fatalf("unexpected Retry-After date duration: %s", wait)
	}
}

func TestHTTPClientReturns429WithoutRetrying(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("account temporarily locked"))
	}))
	defer srv.Close()

	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{srv.URL}
	client, err := New(cfg, scope.NewEngine(cfg), ratelimit.New(1000, 1000))
	if err != nil {
		t.Fatal(err)
	}
	rr, err := client.Do(context.Background(), http.MethodPost, srv.URL, []byte("x=1"), nil)
	if err != nil {
		t.Fatalf("429 must be returned as evidence, got error: %v", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("429 was retried %d times", requests.Load())
	}
	if rr.Response.StatusCode != http.StatusTooManyRequests || rr.Response.Body != "account temporarily locked" {
		t.Fatalf("429 evidence was not preserved: %+v", rr.Response)
	}
}

func TestHTTPClientEnforcesGlobalRequestBudget(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{srv.URL}
	cfg.RequestBudget = 1
	client, err := New(cfg, scope.NewEngine(cfg), ratelimit.New(1000, 1000))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Do(context.Background(), http.MethodGet, srv.URL, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Do(context.Background(), http.MethodGet, srv.URL, nil, nil); err == nil || !strings.Contains(err.Error(), "request budget exhausted") {
		t.Fatalf("second request should exhaust budget, got %v", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("budget allowed %d network requests, want 1", requests.Load())
	}
}

func TestHTTPClientAppliesExplicitHostOverride(t *testing.T) {
	var gotHost, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost, gotMethod = r.Host, r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{srv.URL}
	client, err := New(cfg, scope.NewEngine(cfg), ratelimit.New(1000, 1000))
	if err != nil {
		t.Fatal(err)
	}
	rr, err := client.Do(context.Background(), http.MethodGet, srv.URL, nil, map[string]string{"Host": "canary.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	if gotHost != "canary.invalid" || gotMethod != http.MethodGet {
		t.Fatalf("server observed Host=%q method=%q", gotHost, gotMethod)
	}
	if rr.Request.Headers["Host"] != "canary.invalid" {
		t.Fatalf("evidence did not preserve Host override: %+v", rr.Request.Headers)
	}
}

func TestHTTPClientRoutesRequestsThroughConfiguredProxy(t *testing.T) {
	var requests atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.String() != "http://allowed.test/probe" {
			t.Errorf("proxy did not receive absolute target URL: %q", r.URL.String())
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("proxied"))
	}))
	defer proxy.Close()

	cfg := config.DefaultScanConfig()
	cfg.ProxyURL = strings.TrimPrefix(proxy.URL, "http://") // host:port shorthand
	cfg.IncludeDomains = []string{"allowed.test"}
	client, err := New(cfg, scope.NewEngine(cfg), ratelimit.New(1000, 1000))
	if err != nil {
		t.Fatal(err)
	}
	rr, err := client.Do(context.Background(), http.MethodGet, "http://allowed.test/probe", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 || rr.Response.Body != "proxied" {
		t.Fatalf("request bypassed proxy: requests=%d body=%q", requests.Load(), rr.Response.Body)
	}
}

func TestHTTPClientProxyAuthenticationAndInsecureTLSConfig(t *testing.T) {
	var auth string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Proxy-Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()

	cfg := config.DefaultScanConfig()
	cfg.ProxyURL = strings.Replace(proxy.URL, "http://", "http://user:secret@", 1)
	cfg.InsecureSkipVerify = true
	cfg.IncludeDomains = []string{"allowed.test"}
	client, err := New(cfg, scope.NewEngine(cfg), ratelimit.New(1000, 1000))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Do(context.Background(), http.MethodGet, "http://allowed.test/", nil, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(auth, "Basic ") {
		t.Fatalf("proxy credentials were not sent: %q", auth)
	}
	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("insecure TLS setting was not propagated to proxy-aware transport")
	}
}

func TestHostCircuitOpensAfterRepeatedBlocks(t *testing.T) {
	c := &Client{hostBlocks: map[string]int{}, blockedUntil: map[string]time.Time{}}
	for i := 0; i < 3; i++ {
		c.recordHostBlock("example.com", time.Second)
	}
	if _, open := c.circuitOpen("example.com"); !open {
		t.Fatal("expected host circuit to open after repeated blocks")
	}
	c.clearHostBlocks("example.com")
	if _, open := c.circuitOpen("example.com"); open {
		t.Fatal("expected successful recovery to close circuit")
	}
}

func TestHTTPClientScopeBlocking(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"allowed.test"}
	cfg.RedactionEnabled = true
	scopeEngine := scope.NewEngine(cfg)
	client, err := New(cfg, scopeEngine, ratelimit.New(1000, 1000))
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Do(context.Background(), "GET", srv.URL, nil, nil)
	if err == nil {
		t.Fatal("expected scope block for out-of-scope host")
	}
}

func TestSensitiveHeaderRedactionPreservesRawValues(t *testing.T) {
	rr := RequestResponse{
		Request:  RequestRecord{Headers: map[string]string{"Authorization": "secret"}},
		Response: ResponseRecord{Headers: map[string]string{"Set-Cookie": "a=b"}},
	}
	redacted := Redact(rr)
	if redacted.Request.Headers["Authorization"] != "secret" {
		t.Fatal("authorization was unexpectedly redacted")
	}
	if redacted.Response.Headers["Set-Cookie"] != "a=b" {
		t.Fatal("set-cookie was unexpectedly redacted")
	}
}

func TestWAFBypassHeadersDefaultOnAndCanBeDisabled(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{srv.URL}
	scopeEngine := scope.NewEngine(cfg)
	client, err := New(cfg, scopeEngine, ratelimit.New(1000, 1000))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Do(context.Background(), "GET", srv.URL, nil, nil); err != nil {
		t.Fatal(err)
	}
	if got.Get("X-Forwarded-For") != "" || got.Get("CF-Connecting-IP") != "" {
		t.Fatalf("default scan config should NOT add WAF bypass headers: %v", got)
	}

	cfg.EnableWAFBypassHeaders = true
	client, err = New(cfg, scopeEngine, ratelimit.New(1000, 1000))
	if err != nil {
		t.Fatal(err)
	}
	got = nil
	if _, err := client.Do(context.Background(), "GET", srv.URL, nil, nil); err != nil {
		t.Fatal(err)
	}
	if got.Get("X-Forwarded-For") == "" || got.Get("CF-Connecting-IP") == "" {
		t.Fatalf("explicitly enabled WAF evasion should add bypass headers: %v", got)
	}
}

func TestHTTPClientRedirectTracking(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if r.URL.Path == "/login" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body>Login Page</body></html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cfg := config.DefaultScanConfig()
	cfg.FollowRedirects = true
	cfg.IncludeDomains = []string{srv.URL}
	scopeEngine := scope.NewEngine(cfg)
	client, err := New(cfg, scopeEngine, ratelimit.New(1000, 1000))
	if err != nil {
		t.Fatal(err)
	}

	rr, err := client.Do(context.Background(), "GET", srv.URL+"/v1", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !rr.Response.Redirected {
		t.Fatal("expected Redirected to be true")
	}
	if rr.Response.InitialStatus != 302 {
		t.Fatalf("expected InitialStatus = 302, got %d", rr.Response.InitialStatus)
	}
	if rr.Response.StatusCode != 200 {
		t.Fatalf("expected final StatusCode = 200, got %d", rr.Response.StatusCode)
	}
	if !strings.HasSuffix(rr.Response.FinalURL, "/login") {
		t.Fatalf("expected FinalURL to end with /login, got %s", rr.Response.FinalURL)
	}
}

