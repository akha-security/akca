package httpclient

import (
	"context"
	"io"
	"sync"
)

func (c *Client) ApplyTrafficBudget(globalRate, hostRate float64, globalLimit, hostLimit int) {
	c.limiter.SetRates(globalRate, hostRate)
	c.trafficMu.Lock()
	defer c.trafficMu.Unlock()
	c.globalLimit, c.hostLimit = globalLimit, hostLimit
	if c.trafficChanged != nil {
		close(c.trafficChanged)
	}
	c.trafficChanged = make(chan struct{})
}

func (c *Client) acquireHTTP(ctx context.Context, host string) (func(), error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c.trafficMu.Lock()
		if (c.globalLimit <= 0 || c.activeHTTP < c.globalLimit) && (c.hostLimit <= 0 || c.activeHosts[host] < c.hostLimit) {
			if c.activeHosts == nil {
				c.activeHosts = map[string]int{}
			}
			c.activeHTTP++
			c.activeHosts[host]++
			c.trafficMu.Unlock()
			var once sync.Once
			return func() {
				once.Do(func() {
					c.trafficMu.Lock()
					defer c.trafficMu.Unlock()
					c.activeHTTP--
					c.activeHosts[host]--
					if c.trafficChanged != nil {
						close(c.trafficChanged)
					}
					c.trafficChanged = make(chan struct{})
				})
			}, nil
		}
		if c.trafficChanged == nil {
			c.trafficChanged = make(chan struct{})
		}
		changed := c.trafficChanged
		c.trafficMu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-changed:
		}
	}
}

type admissionBody struct {
	io.ReadCloser
	release func()
}

func (b *admissionBody) Close() error { defer b.release(); return b.ReadCloser.Close() }
