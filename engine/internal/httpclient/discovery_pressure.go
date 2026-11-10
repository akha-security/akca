package httpclient

import (
	"context"
	"errors"
	"net/url"
	"time"
)

var ErrHostDeferred = errors.New("active discovery deferred after WAF/rate-limit response")

type discoveryPressureKey struct{}
type activeScanKey struct{}

func WithActiveScan(ctx context.Context) context.Context {
	return context.WithValue(ctx, activeScanKey{}, true)
}

func WithBackgroundDiscovery(ctx context.Context) context.Context {
	return context.WithValue(ctx, discoveryPressureKey{}, true)
}

func (c *Client) discoveryDeferred(ctx context.Context, host string) bool {
	background, _ := ctx.Value(discoveryPressureKey{}).(bool)
	active, _ := ctx.Value(activeScanKey{}).(bool)
	if !background && !active {
		return false
	}
	c.blockMu.Lock()
	defer c.blockMu.Unlock()
	return (background && c.hostBlocks[host] > 0) || (active && c.hostBlocks[host] >= 2)
}

func (c *Client) RecoverHost(ctx context.Context, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	host := u.Hostname()
	c.blockMu.Lock()
	if c.hostBlocks[host] == 0 {
		c.blockMu.Unlock()
		return nil
	}
	probe := c.healthyProbe[host]
	if probe == "" || c.recoveryAttempted[host] {
		c.blockMu.Unlock()
		return ErrHostDeferred
	}
	if c.recoveryAttempted == nil {
		c.recoveryAttempted = map[string]bool{}
	}
	c.recoveryAttempted[host] = true
	c.blockMu.Unlock()
	ctx = context.WithValue(ctx, discoveryPressureKey{}, false)
	ctx = context.WithValue(ctx, activeScanKey{}, false)
	ctx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	for i := 0; i < 3; i++ {
		rr, err := c.Do(ctx, "GET", probe, nil, nil)
		if err != nil || rr.Response.StatusCode < 200 || rr.Response.StatusCode >= 300 {
			return ErrHostDeferred
		}
	}
	if c.HostUnderPressure(rawURL) {
		return ErrHostDeferred
	}
	return nil
}

func (c *Client) recordSuccessfulRequest(host, method, rawURL string) bool {
	c.blockMu.Lock()
	if c.healthyProbe == nil {
		c.healthyProbe = map[string]string{}
	}
	if c.hostBlocks[host] == 0 && method == "GET" && c.healthyProbe[host] == "" {
		c.healthyProbe[host] = rawURL
	}
	known := c.hostBlocks[host] == 0 || (method == "GET" && c.healthyProbe[host] == rawURL)
	c.blockMu.Unlock()
	if known {
		c.recordHostSuccess(host)
	}
	return known
}

func (c *Client) HostUnderPressure(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	c.blockMu.Lock()
	defer c.blockMu.Unlock()
	return c.hostBlocks[u.Hostname()] > 0
}

// HostCooldownRemaining reports the current server/WAF wait for a URL. The
// crawler uses it to keep its per-request deadline from expiring before the
// HTTP client is allowed to send the request.
func (c *Client) HostCooldownRemaining(rawURL string) time.Duration {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return 0
	}
	until, blocked := c.circuitOpen(u.Hostname())
	if !blocked {
		return 0
	}
	return time.Until(until)
}
