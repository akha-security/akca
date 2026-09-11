package modules

import (
	"context"
	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"sync"
	"sync/atomic"
)

type targetRun struct {
	requests atomic.Int64
	failures atomic.Int64
	evidence atomic.Bool
	mu       sync.Mutex
	skip     string
}
type targetRunKey struct{}

func (s *targetRun) skipped(reason string) {
	if s != nil {
		s.mu.Lock()
		s.skip = reason
		s.mu.Unlock()
	}
}
func noteExchange(ctx context.Context, err error) {
	if s, ok := ctx.Value(targetRunKey{}).(*targetRun); ok {
		s.requests.Add(1)
		if err != nil {
			s.failures.Add(1)
		} else {
			s.evidence.Store(true)
		}
	}
}
func noteCachedEvidence(ctx context.Context) {
	if s, ok := ctx.Value(targetRunKey{}).(*targetRun); ok {
		s.evidence.Store(true)
	}
}

type observedHTTP struct{ HTTPDoer }

func (c observedHTTP) Do(ctx context.Context, m, u string, b []byte, h map[string]string) (httpclient.RequestResponse, error) {
	rr, err := c.HTTPDoer.Do(ctx, m, u, b, h)
	noteExchange(ctx, err)
	return rr, err
}
func (c observedHTTP) ReserveExternal(ctx context.Context, rawURL, transport string) error {
	if guard, ok := c.HTTPDoer.(interface {
		ReserveExternal(context.Context, string, string) error
	}); ok {
		return guard.ReserveExternal(ctx, rawURL, transport)
	}
	return nil
}

type observedAnonymous struct{ base sessionlessHTTPDoer }

func (c observedAnonymous) DoWithoutSession(ctx context.Context, m, u string, b []byte, h map[string]string) (httpclient.RequestResponse, error) {
	rr, err := c.base.DoWithoutSession(ctx, m, u, b, h)
	noteExchange(ctx, err)
	return rr, err
}

type observedProfile struct{ base profiledHTTPDoer }

func (c observedProfile) DoWithAuthProfile(ctx context.Context, m, u string, b []byte, h map[string]string, p config.AuthProfile) (httpclient.RequestResponse, error) {
	rr, err := c.base.DoWithAuthProfile(ctx, m, u, b, h, p)
	noteExchange(ctx, err)
	return rr, err
}

// Preserve optional identity interfaces. Advertising unsupported capabilities
// would change module preconditions and invalidate authorization controls.
func observeHTTP(client HTTPDoer) HTTPDoer {
	b := observedHTTP{client}
	a, hasA := client.(sessionlessHTTPDoer)
	p, hasP := client.(profiledHTTPDoer)
	if hasA && hasP {
		return struct {
			observedHTTP
			observedAnonymous
			observedProfile
		}{b, observedAnonymous{a}, observedProfile{p}}
	}
	if hasA {
		return struct {
			observedHTTP
			observedAnonymous
		}{b, observedAnonymous{a}}
	}
	if hasP {
		return struct {
			observedHTTP
			observedProfile
		}{b, observedProfile{p}}
	}
	return b
}
