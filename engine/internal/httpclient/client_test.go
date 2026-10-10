package httpclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestHTTPClientOpensCircuitOnFirst429WithoutRetryAfter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("too many requests"))
	}))
	defer srv.Close()
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{srv.URL}
	client, err := New(cfg, scope.NewEngine(cfg), ratelimit.New(1000, 1000))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Do(context.Background(), http.MethodGet, srv.URL, nil, nil); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(srv.URL)
	until, open := client.circuitOpen(u.Hostname())
	if !open || time.Until(until) < 25*time.Second {
		t.Fatalf("first 429 without Retry-After did not open a protective circuit: open=%v until=%v", open, until)
	}
}

func TestExpectedRateLimitResponseDoesNotOpenGlobalCircuit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("account rate limit reached"))
	}))
	defer srv.Close()
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{srv.URL}
	client, err := New(cfg, scope.NewEngine(cfg), ratelimit.New(1000, 1000))
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithExpectedRateLimitResponse(context.Background())
	rr, err := client.Do(ctx, http.MethodPost, srv.URL, []byte("account=known"), nil)
	if err != nil || rr.Response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 evidence, response=%+v err=%v", rr.Response, err)
	}
	u, _ := url.Parse(srv.URL)
	if _, open := client.circuitOpen(u.Hostname()); open {
		t.Fatal("deliberate rate-limit verification must not park unrelated host traffic")
	}
}

func TestHTTPClientOpensCircuitOnWAFChallengeBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Web Application Firewall: request blocked; support ID 42"))
	}))
	defer srv.Close()
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{srv.URL}
	client, err := New(cfg, scope.NewEngine(cfg), ratelimit.New(1000, 1000))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Do(context.Background(), http.MethodGet, srv.URL, nil, nil); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(srv.URL)
	if _, open := client.circuitOpen(u.Hostname()); !open {
		t.Fatal("WAF challenge response did not open the host circuit")
	}
}

func TestHostBlockRequiresThreeHealthyResponsesToClear(t *testing.T) {
	client := &Client{hostBlocks: map[string]int{}, hostHealthy: map[string]int{}, blockedUntil: map[string]time.Time{}}
	client.recordHostBlock("example.com", 30*time.Second)
	client.recordHostSuccess("example.com")
	client.recordHostSuccess("example.com")
	if _, open := client.circuitOpen("example.com"); !open {
		t.Fatal("two healthy responses must not immediately erase host pressure history")
	}
	client.recordHostSuccess("example.com")
	if _, open := client.circuitOpen("example.com"); open {
		t.Fatal("three consecutive healthy responses should clear the host circuit")
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
	if !ok {
		if wt, isWT := client.httpClient.Transport.(*WireTransport); isWT {
			transport, ok = wt.base.(*http.Transport)
		}
	}
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

func TestHTTPClientWaitsForHostCircuitInsteadOfSkippingRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{srv.URL}
	client, err := New(cfg, scope.NewEngine(cfg), ratelimit.New(1000, 1000))
	if err != nil {
		t.Fatal(err)
	}
	host, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	client.blockedUntil[host.Hostname()] = time.Now().Add(40 * time.Millisecond)

	started := time.Now()
	if _, err := client.Do(context.Background(), http.MethodGet, srv.URL, nil, nil); err != nil {
		t.Fatalf("request was skipped while the host circuit was cooling down: %v", err)
	}
	if elapsed := time.Since(started); elapsed < 25*time.Millisecond {
		t.Fatalf("request ignored the host cooldown: elapsed=%s", elapsed)
	}
}

func TestHostCircuitWaitHonorsCancellation(t *testing.T) {
	client := &Client{hostBlocks: map[string]int{}, blockedUntil: map[string]time.Time{
		"example.com": time.Now().Add(time.Minute),
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.waitForHostCircuit(ctx, "example.com"); !errors.Is(err, context.Canceled) {
		t.Fatalf("wait error = %v, want context cancellation", err)
	}
}

func TestHostCircuitWaitObservesConcurrentRecovery(t *testing.T) {
	client := &Client{hostBlocks: map[string]int{"example.com": 3}, blockedUntil: map[string]time.Time{
		"example.com": time.Now().Add(time.Minute),
	}}
	go func() {
		time.Sleep(25 * time.Millisecond)
		client.clearHostBlocks("example.com")
	}()

	started := time.Now()
	if err := client.waitForHostCircuit(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("circuit recovery was not observed promptly: %s", elapsed)
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

func TestShouldStripAuthOnRedirect(t *testing.T) {
	tests := []struct {
		name     string
		prev     string
		next     string
		expected bool
	}{
		{
			name:     "same origin https",
			prev:     "https://example.com/login",
			next:     "https://example.com/dashboard",
			expected: false,
		},
		{
			name:     "https to http downgrade on same host",
			prev:     "https://example.com/auth",
			next:     "http://example.com/insecure",
			expected: true,
		},
		{
			name:     "cross host redirect",
			prev:     "https://example.com/out",
			next:     "https://other.com/landing",
			expected: true,
		},
		{
			name:     "cross port redirect",
			prev:     "https://example.com:8443/api",
			next:     "https://example.com:9443/api",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u1, _ := url.Parse(tt.prev)
			u2, _ := url.Parse(tt.next)
			res := shouldStripAuthOnRedirect(u1, u2)
			if res != tt.expected {
				t.Errorf("shouldStripAuthOnRedirect(%s -> %s) = %v; want %v", tt.prev, tt.next, res, tt.expected)
			}
		})
	}
}

func TestWireTransport_RedirectConsumesNetworkAttempts(t *testing.T) {
	var serverHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverHits.Add(1)
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/destination", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{srv.URL}
	cfg.FollowRedirects = true
	cfg.RequestBudget = 1 // Budget is 1 wire request! The initial request succeeds, but redirect hop must be blocked.

	client, err := New(cfg, scope.NewEngine(cfg), ratelimit.New(1000, 1000))
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Do(context.Background(), http.MethodGet, srv.URL+"/start", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "request budget exhausted") {
		t.Fatalf("expected redirect to be blocked by budget exhaustion, got err: %v", err)
	}
	if serverHits.Load() != 1 {
		t.Fatalf("expected exactly 1 wire request before budget block, got %d", serverHits.Load())
	}
}
