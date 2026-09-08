package httpclient

import (
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/akha-security/akca/engine/internal/ratelimit"
)

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
	if w.networkAttempts != nil {
		attempts := w.networkAttempts.Add(1)
		if w.maxBudget > 0 && attempts > int64(w.maxBudget) {
			return nil, fmt.Errorf("global request budget exhausted after %d requests", w.maxBudget)
		}
	}

	if w.limiter != nil && req.URL != nil {
		host := req.URL.Hostname()
		if host != "" {
			if err := w.limiter.WaitContext(req.Context(), host); err != nil {
				return nil, err
			}
		}
	}

	return w.base.RoundTrip(req)
}
