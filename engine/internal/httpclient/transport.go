package httpclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/akha-security/akca/engine/internal/ratelimit"
)

var ErrOutsideScope = errors.New("target is outside scan scope")

// ReserveBrowserResource admits explicit passive dependencies without expanding scan scope.
func (c *Client) ReserveBrowserResource(ctx context.Context, rawURL, transport string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return ErrOutsideScope
	}
	for _, domain := range c.cfg.BrowserResourceDomains {
		if strings.EqualFold(strings.TrimSpace(domain), u.Hostname()) {
			return reserveNetwork(ctx, u, c.limiter, &c.networkAttempts, c.cfg.RequestBudget)
		}
	}
	return ErrOutsideScope
}

// WireTransport intercepts every physical outbound HTTP transaction (including retries and redirects).
type WireTransport struct {
	base            http.RoundTripper
	limiter         *ratelimit.Limiter
	networkAttempts *atomic.Int64
	maxBudget       int
}

func NewWireTransport(base http.RoundTripper, limiter *ratelimit.Limiter, counter *atomic.Int64, maxBudget int) *WireTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &WireTransport{
		base:            base,
		limiter:         limiter,
		networkAttempts: counter,
		maxBudget:       maxBudget,
	}
}

func (w *WireTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := reserveNetwork(req.Context(), req.URL, w.limiter, w.networkAttempts, w.maxBudget); err != nil {
		return nil, err
	}
	return w.base.RoundTrip(req)
}

func reserveNetwork(ctx context.Context, u *url.URL, limiter *ratelimit.Limiter, counter *atomic.Int64, maxBudget int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if counter != nil && maxBudget > 0 && counter.Load() >= int64(maxBudget) {
		return fmt.Errorf("global request budget exhausted after %d requests", maxBudget)
	}
	if limiter != nil && u != nil && u.Hostname() != "" {
		if err := limiter.WaitContext(ctx, u.Hostname()); err != nil {
			return err
		}
	}
	if err := ReserveRequestBudget(ctx); err != nil {
		return err
	}
	if counter != nil {
		for {
			n := counter.Load()
			if maxBudget > 0 && n >= int64(maxBudget) {
				return fmt.Errorf("global request budget exhausted after %d requests", maxBudget)
			}
			if counter.CompareAndSwap(n, n+1) {
				break
			}
		}
	}
	return nil
}

// ReserveExternal accounts for raw protocol and browser requests using the same
// atomic budget and host limiter as HTTP retries and redirects.
func (c *Client) ReserveExternal(ctx context.Context, rawURL, transport string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	if u.Scheme == "ws" {
		u.Scheme = "http"
	}
	if u.Scheme == "wss" {
		u.Scheme = "https"
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("invalid %s target", transport)
	}
	if c.scope != nil && !c.scope.IsInScope(u.String()) {
		return fmt.Errorf("%s: %w", transport, ErrOutsideScope)
	}
	return reserveNetwork(ctx, u, c.limiter, &c.networkAttempts, c.cfg.RequestBudget)
}
