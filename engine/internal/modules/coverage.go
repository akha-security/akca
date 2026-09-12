package modules

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
)

type targetRun struct {
	requests        atomic.Int64
	failures        atomic.Int64
	evidence        atomic.Bool
	mu              sync.Mutex
	skip            string
	managed         bool
	reserve         func() error
	budgetExhausted atomic.Bool
	interrupted     atomic.Bool
	pendingTiming   atomic.Int64
}
type targetRunKey struct{}

func withTargetRun(ctx context.Context, s *targetRun) context.Context {
	ctx = context.WithValue(ctx, targetRunKey{}, s)
	if s.reserve != nil {
		ctx = httpclient.WithRequestBudget(ctx, func() error {
			if err := ctx.Err(); err != nil {
				return err
			}
			err := s.reserve()
			if err != nil {
				s.budgetExhausted.Store(true)
				s.skipped(err.Error())
			}
			return err
		})
	}
	return ctx
}

func managedTarget(ctx context.Context) bool {
	s, _ := ctx.Value(targetRunKey{}).(*targetRun)
	return s != nil && s.managed
}

func reserveClientBudget(ctx context.Context, client interface{}) error {
	if s, ok := ctx.Value(targetRunKey{}).(*targetRun); ok && s.budgetExhausted.Load() {
		return fmt.Errorf("request budget exhausted for target allocation")
	}
	if c, ok := client.(interface{ RequestBudgetAtTransport() bool }); ok && c.RequestBudgetAtTransport() {
		return nil
	}
	return httpclient.ReserveRequestBudget(ctx)
}

func (s *targetRun) skipped(reason string) {
	if s != nil {
		s.mu.Lock()
		s.skip = reason
		s.mu.Unlock()
	}
}
func noteExchange(ctx context.Context, err error) {
	if s, ok := ctx.Value(targetRunKey{}).(*targetRun); ok {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			s.interrupted.Store(true)
		}
		if err != nil && strings.Contains(err.Error(), "request budget exhausted") {
			s.budgetExhausted.Store(true)
			s.skipped(err.Error())
			return
		}
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
	if err := reserveClientBudget(ctx, c.HTTPDoer); err != nil {
		noteExchange(ctx, err)
		return httpclient.RequestResponse{}, err
	}
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
	if err := reserveClientBudget(ctx, c.base); err != nil {
		noteExchange(ctx, err)
		return httpclient.RequestResponse{}, err
	}
	rr, err := c.base.DoWithoutSession(ctx, m, u, b, h)
	noteExchange(ctx, err)
	return rr, err
}

type observedProfile struct{ base profiledHTTPDoer }

func (c observedProfile) DoWithAuthProfile(ctx context.Context, m, u string, b []byte, h map[string]string, p config.AuthProfile) (httpclient.RequestResponse, error) {
	if err := reserveClientBudget(ctx, c.base); err != nil {
		noteExchange(ctx, err)
		return httpclient.RequestResponse{}, err
	}
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
