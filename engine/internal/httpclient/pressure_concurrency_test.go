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

	activeCtx := WithActiveScan(WithBackgroundDiscovery(context.Background()))
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

func TestQueuedRequestGetsFullWireTimeoutAfterCooldown(t *testing.T) {
	var wireDeadline time.Duration
	c := pressureClient(t, pressureTransport(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok {
			t.Fatal("wire request did not have a deadline")
		}
		wireDeadline = time.Until(deadline)
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
	}))
	// Simulate another worker opening the circuit while this request is
	// waiting for admission, after Do has already checked the host once.
	transport := c.httpClient.Transport.(*WireTransport)
	admit := transport.admit
	transport.admit = func(ctx context.Context, host string) (func(), error) {
		c.blockMu.Lock()
		c.blockedUntil[host] = time.Now().Add(65 * time.Millisecond)
		c.blockMu.Unlock()
		return admit(ctx, host)
	}
	c.httpClient.Timeout = 10 * time.Millisecond
	rr, err := c.Do(context.Background(), http.MethodGet, "https://example.test/queued", nil, nil)
	if err != nil {
		t.Fatalf("cooldown expired the wire timeout before the request: %v", err)
	}
	if wireDeadline < wireRequestTimeout-time.Second {
		t.Fatalf("remaining wire timeout = %s", wireDeadline)
	}
	if rr.Response.Duration >= 65*time.Millisecond {
		t.Fatalf("cooldown was reported as response latency: %s", rr.Response.Duration)
	}
	if got := c.TotalRequests(); got != 1 {
		t.Fatalf("wire requests = %d, want 1", got)
	}
}

func TestDeferredQueuedRequestDoesNotSpendBudget(t *testing.T) {
	c := pressureClient(t, pressureTransport(func(r *http.Request) (*http.Response, error) {
		t.Fatal("deferred request reached the network")
		return nil, nil
	}))
	transport := c.httpClient.Transport.(*WireTransport)
	transport.admit = func(_ context.Context, host string) (func(), error) {
		c.recordHostBlock(host, time.Minute)
		return func() {}, nil
	}
	reservations := 0
	ctx := WithRequestBudget(WithBackgroundDiscovery(context.Background()), func() error {
		reservations++
		return nil
	})
	_, err := c.Do(ctx, http.MethodGet, "https://example.test/queued", nil, nil)
	if !errors.Is(err, ErrHostDeferred) || c.TotalRequests() != 0 || reservations != 0 {
		t.Fatalf("defer error = %v, physical attempts = %d, reservations = %d", err, c.TotalRequests(), reservations)
	}
}
