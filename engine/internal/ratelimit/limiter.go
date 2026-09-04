package ratelimit

import (
	"context"
	"sync"
	"time"
)

type Limiter struct {
	mu            sync.Mutex
	globalRPS     float64
	perHostRPS    float64
	globalNext    time.Time
	hostNext      map[string]time.Time
	wafMultiplier float64
}

func New(globalRPS, perHostRPS float64) *Limiter {
	return &Limiter{
		globalRPS:     globalRPS,
		perHostRPS:    perHostRPS,
		hostNext:      make(map[string]time.Time),
		wafMultiplier: 1,
	}
}

func (l *Limiter) SetWAFSlowDown(multiplier float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if multiplier < 1 {
		multiplier = 1
	}
	if multiplier > 50.0 {
		multiplier = 50.0
	}
	l.wafMultiplier = multiplier
}

// SetRates updates the limiter after runtime WAF fingerprinting. Existing
// reservations are cleared so stale high-rate slots do not leak into the new
// cautious budget.
func (l *Limiter) SetRates(globalRPS, perHostRPS float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.globalRPS = globalRPS
	l.perHostRPS = perHostRPS
	l.globalNext = time.Time{}
	l.hostNext = make(map[string]time.Time)
	l.wafMultiplier = 1
}

func (l *Limiter) Rates() (globalRPS, perHostRPS, wafMultiplier float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.globalRPS, l.perHostRPS, l.wafMultiplier
}

func (l *Limiter) DecayWAFSlowDown(amount float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.wafMultiplier > 1.0 {
		l.wafMultiplier -= amount
		if l.wafMultiplier < 1.0 {
			l.wafMultiplier = 1.0
		}
	}
}

func (l *Limiter) Wait(host string) {
	_ = l.WaitContext(context.Background(), host)
}

func (l *Limiter) WaitContext(ctx context.Context, host string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// reserveWait atomically claims this caller's slot and returns how long to
	// wait for it. It must be called exactly once per request: calling it in a
	// loop would re-claim a fresh slot on every wakeup, so multiple concurrent
	// callers would push the next-allowed time forward faster than real time and
	// starve forever (livelock).
	wait := l.reserveWait(host)
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func (l *Limiter) reserveWait(host string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	var waits []time.Duration

	if l.globalRPS > 0 {
		interval := time.Duration(float64(time.Second) / (l.globalRPS / l.wafMultiplier))
		// Apply subtle non-periodic jitter (up to 10%) so requests appear organic
		jitterNanos := (now.UnixNano() % int64(max(int(interval/10), 1)))
		interval += time.Duration(jitterNanos)
		if now.Before(l.globalNext) {
			waits = append(waits, l.globalNext.Sub(now))
		} else {
			l.globalNext = now
		}
		l.globalNext = maxTime(l.globalNext, now).Add(interval)
	}

	if l.perHostRPS > 0 && host != "" {
		interval := time.Duration(float64(time.Second) / (l.perHostRPS / l.wafMultiplier))
		jitterNanos := (now.UnixNano() % int64(max(int(interval/10), 1)))
		interval += time.Duration(jitterNanos)
		next := l.hostNext[host]
		if now.Before(next) {
			waits = append(waits, next.Sub(now))
		}
		l.hostNext[host] = maxTime(next, now).Add(interval)
	}

	return maxDuration(waits)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func maxDuration(items []time.Duration) time.Duration {
	var max time.Duration
	for _, d := range items {
		if d > max {
			max = d
		}
	}
	return max
}
