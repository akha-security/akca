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

func TestSensitiveHeaderRedaction(t *testing.T) {
	rr := RequestResponse{
		Request:  RequestRecord{Headers: map[string]string{"Authorization": "secret"}},
		Response: ResponseRecord{Headers: map[string]string{"Set-Cookie": "a=b"}},
	}
	redacted := Redact(rr)
	if redacted.Request.Headers["Authorization"] != "[REDACTED]" {
		t.Fatal("authorization not redacted")
	}
	if redacted.Response.Headers["Set-Cookie"] != "[REDACTED]" {
		t.Fatal("set-cookie not redacted")
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
	if got.Get("X-Forwarded-For") == "" || got.Get("CF-Connecting-IP") == "" {
		t.Fatalf("expected default WAF evasion headers: %v", got)
	}

	cfg.EnableWAFBypassHeaders = false
	client, err = New(cfg, scopeEngine, ratelimit.New(1000, 1000))
	if err != nil {
		t.Fatal(err)
	}
	got = nil
	if _, err := client.Do(context.Background(), "GET", srv.URL, nil, nil); err != nil {
		t.Fatal(err)
	}
	if got.Get("X-Forwarded-For") != "" || got.Get("CF-Connecting-IP") != "" {
		t.Fatalf("disabled WAF evasion should not add bypass headers: %v", got)
	}
}
