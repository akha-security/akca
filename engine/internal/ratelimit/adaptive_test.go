package ratelimit

import (
	"testing"
)

func TestAdaptiveLimiterAIMD(t *testing.T) {
	al := NewAdaptiveLimiter(10.0, 1.0, 20.0)

	if al.CurrentRPS() != 10.0 {
		t.Fatalf("expected initial RPS 10.0, got %f", al.CurrentRPS())
	}

	// 1. Trigger 429 Rate Limit (Multiplicative Decrease)
	al.RecordResponse(429)
	if al.CurrentRPS() != 5.0 {
		t.Fatalf("expected halved RPS 5.0 after 429, got %f", al.CurrentRPS())
	}

	// 2. Trigger another 429 after cooldown bypass
	al.lastSlowdown = al.lastSlowdown.Add(-10 * 1e9)
	al.RecordResponse(429)
	if al.CurrentRPS() != 2.5 {
		t.Fatalf("expected halved RPS 2.5 after second 429, got %f", al.CurrentRPS())
	}

	// 3. Trigger consecutive successful 200 OK responses (Additive Increase)
	for i := 0; i < 15; i++ {
		al.RecordResponse(200)
	}

	if al.CurrentRPS() != 3.5 {
		t.Fatalf("expected stepped up RPS 3.5 (+1.0), got %f", al.CurrentRPS())
	}
}
