package ratelimit

import (
	"sync"
	"time"
)

// AdaptiveLimiter manages dynamic AIMD (Additive Increase, Multiplicative Decrease)
// rate limiting based on real-time server feedback and 429/503 responses.
type AdaptiveLimiter struct {
	mu                sync.Mutex
	baseLimiter       *Limiter
	minRPS            float64
	maxRPS            float64
	currentRPS        float64
	consecutiveOK     int
	thresholdToStepUp int
	lastSlowdown      time.Time
	cooldownDuration  time.Duration
}

// NewAdaptiveLimiter creates a new AdaptiveLimiter with configured min, max and initial rates.
func NewAdaptiveLimiter(initialRPS, minRPS, maxRPS float64) *AdaptiveLimiter {
	if minRPS <= 0 {
		minRPS = 0.5
	}
	if maxRPS <= 0 {
		maxRPS = 50.0
	}
	if initialRPS <= 0 {
		initialRPS = 10.0
	}

	base := New(initialRPS, initialRPS)
	return &AdaptiveLimiter{
		baseLimiter:       base,
		minRPS:            minRPS,
		maxRPS:            maxRPS,
		currentRPS:        initialRPS,
		thresholdToStepUp: 15,
		cooldownDuration:  3 * time.Second,
	}
}

// BaseLimiter returns the underlying Limiter instance.
func (al *AdaptiveLimiter) BaseLimiter() *Limiter {
	return al.baseLimiter
}

// RecordResponse updates the adaptive model based on the target response status.
func (al *AdaptiveLimiter) RecordResponse(statusCode int) {
	al.mu.Lock()
	defer al.mu.Unlock()

	now := time.Now()

	// 1. If Rate Limited (429 Too Many Requests) or Service Overloaded (503)
	if statusCode == 429 || statusCode == 503 {
		al.consecutiveOK = 0
		if now.Sub(al.lastSlowdown) > al.cooldownDuration {
			// Multiplicative Decrease (halve RPS down to minRPS)
			al.currentRPS = al.currentRPS * 0.5
			if al.currentRPS < al.minRPS {
				al.currentRPS = al.minRPS
			}
			al.baseLimiter.SetRates(al.currentRPS, al.currentRPS)
			al.baseLimiter.SetWAFSlowDown(2.0)
			al.lastSlowdown = now
		}
		return
	}

	// 2. Normal Success (2xx / 3xx / 4xx other than 429)
	if statusCode >= 200 && statusCode < 500 {
		al.consecutiveOK++
		if al.consecutiveOK >= al.thresholdToStepUp {
			al.consecutiveOK = 0
			// Additive Increase (+1.0 RPS up to maxRPS)
			if al.currentRPS < al.maxRPS {
				al.currentRPS += 1.0
				if al.currentRPS > al.maxRPS {
					al.currentRPS = al.maxRPS
				}
				al.baseLimiter.SetRates(al.currentRPS, al.currentRPS)
				al.baseLimiter.DecayWAFSlowDown(0.2)
			}
		}
	}
}

// CurrentRPS returns the currently adapted requests-per-second limit.
func (al *AdaptiveLimiter) CurrentRPS() float64 {
	al.mu.Lock()
	defer al.mu.Unlock()
	return al.currentRPS
}
