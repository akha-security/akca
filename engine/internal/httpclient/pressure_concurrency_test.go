package httpclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/ratelimit"
	"github.com/akha-security/akca/engine/internal/scope"
)

type pressureTransport func(*http.Request) (*http.Response, error)

func (f pressureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func pressureClient(t *testing.T, transport http.RoundTripper) *Client {
	t.Helper()
	cfg := config.DefaultScanConfig()
	cfg.Targets = []string{"https://example.test"}
	cfg.IncludeDomains = []string{"example.test"}
	cfg.TestRoundTripper = transport
	c, err := New(cfg, scope.NewEngine(cfg), ratelimit.New(10000, 10000))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTrafficBudgetHoldsConcurrencyUntilResponseBodyCloses(t *testing.T) {
	c := pressureClient(t, pressureTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
	}))
	c.ApplyTrafficBudget(10000, 10000, 2, 1)
	first, err := c.HTTPClient().Get("https://example.test/first")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Body.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err = c.Do(ctx, "GET", "https://example.test/second", nil, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("per-host cap not enforced: %v", err)
	}
	if c.TotalRequests() != 1 {
		t.Fatalf("waiting request consumed network budget: %d", c.TotalRequests())
	}
	first.Body.Close()
	if _, err := c.Do(context.Background(), "GET", "https://example.test/third", nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestWAFDeferralAndRecoveryUseKnownHealthyURL(t *testing.T) {
	c := pressureClient(t, pressureTransport(func(r *http.Request) (*http.Response, error) {
		status, body := 200, "healthy page"
		if r.URL.Path == "/blocked" {
			status, body = 403, "Web Application Firewall: request blocked"
		}
		return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	}))
	if _, err := c.Do(context.Background(), "GET", "https://example.test/healthy", nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(context.Background(), "GET", "https://example.test/blocked", nil, nil); err != nil {
		t.Fatal(err)
	}
	before := c.TotalRequests()
	if _, err := c.Do(WithBackgroundDiscovery(context.Background()), "GET", "https://example.test/assets", nil, nil); !errors.Is(err, ErrHostDeferred) {
		t.Fatalf("discovery was not deferred: %v", err)
	}
	if c.TotalRequests() != before {
		t.Fatal("deferred work made another network attempt")
	}
	c.blockMu.Lock()
	c.blockedUntil["example.test"] = time.Now().Add(-time.Second)
	c.blockMu.Unlock()
	for i := 0; i < 3; i++ {
		if _, err := c.Do(context.Background(), "GET", "https://example.test/unrelated", nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if !c.HostUnderPressure("https://example.test") {
		t.Fatal("unrelated 200 responses cleared WAF pressure")
	}
	if err := c.RecoverHost(context.Background(), "https://example.test"); err != nil {
		t.Fatal(err)
	}
	if c.HostUnderPressure("https://example.test") {
		t.Fatal("known healthy recovery did not reopen discovery")
	}
}

func TestActiveScanWaitsForWAFCooldownInsteadOfBeingDeferred(t *testing.T) {
	requests := 0
	c := pressureClient(t, pressureTransport(func(r *http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("payload delivered")), Request: r}, nil
	}))

	c.blockMu.Lock()
	c.hostBlocks["example.test"] = 2
	c.blockedUntil["example.test"] = time.Now().Add(40 * time.Millisecond)
	c.blockMu.Unlock()

	activeCtx := WithActiveScan(context.Background())
	for i := 0; i < 1200; i++ {
		if c.discoveryDeferred(activeCtx, "example.test") {
			t.Fatalf("active target %d of 1200 was permanently deferred", i+1)
		}
	}

	started := time.Now()
	if _, err := c.Do(activeCtx, "GET", "https://example.test/?q=payload", nil, nil); err != nil {
		t.Fatalf("active vulnerability request was deferred: %v", err)
	}
	if requests != 1 {
		t.Fatalf("active vulnerability request count=%d, want 1", requests)
	}
	if elapsed := time.Since(started); elapsed < 25*time.Millisecond {
		t.Fatalf("active request ignored WAF cooldown: %s", elapsed)
	}
}
