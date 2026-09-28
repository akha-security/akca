package httpclient

import (
	"context"
	"errors"
	"fmt"
	"net"
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
	host := strings.ToLower(u.Hostname())
	c.browserDomainMu.RLock()
	_, allowed := c.browserDomains[host]
	c.browserDomainMu.RUnlock()
	if allowed {
		return reserveNetwork(ctx, u, c.limiter, &c.networkAttempts, c.cfg.RequestBudget)
	}
	return ErrOutsideScope
}

// AdmitBrowserResourceDomains adds exact passive dependency hosts learned from
// a successful in-scope HTML document. It does not expand scanner scope: the
// browser guard permits only GET/HEAD Script, Stylesheet, Image, Font and Media
// requests and strips credentials before this method is consulted.
func (c *Client) AdmitBrowserResourceDomains(domains []string) []string {
	if c == nil {
		return nil
	}
	c.browserDomainMu.Lock()
	defer c.browserDomainMu.Unlock()
	var added []string
	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(domain, ".")))
		if !safeLearnedBrowserHost(domain) || len(c.browserDomains) >= 32 {
			continue
		}
		if _, exists := c.browserDomains[domain]; exists {
			continue
		}
		c.browserDomains[domain] = struct{}{}
		added = append(added, domain)
	}
	return added
}

func safeLearnedBrowserHost(host string) bool {
	if host == "" || strings.ContainsAny(host, "/\\@:#?[]") {
		return false
	}
	lower := strings.ToLower(strings.TrimSuffix(host, "."))
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") ||
		strings.HasSuffix(lower, ".local") || strings.HasSuffix(lower, ".internal") ||
		strings.HasSuffix(lower, ".lan") {
		return false
	}
	if ip := net.ParseIP(lower); ip != nil {
		return !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() &&
			!ip.IsLinkLocalMulticast() && !ip.IsUnspecified() && !ip.IsMulticast()
	}
	return strings.Contains(lower, ".")
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
