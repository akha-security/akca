package ratelimit

import (
	"sync"
	"testing"
	"time"
)

func TestLimiterThreadSafe(t *testing.T) {
	// Use a very high RPS so goroutines don't actually sleep; test only concurrency safety.
	l := New(100000, 100000)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.Wait("example.com")
		}()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("limiter concurrent test timed out")
	}
}

// TestConcurrentNoLivelock guards against the regression where reserveWait was
// called in a loop: multiple concurrent callers pushed the next-allowed time
// forward faster than real time and starved forever. With a modest rate, a
// burst of concurrent callers must still all return within a bounded time.
func TestConcurrentNoLivelock(t *testing.T) {
	l := New(50, 50)
	const callers = 32
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.Wait("example.com")
		}()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("rate limiter livelocked under concurrency")
	}
}

// TestPacing verifies the limiter still spaces requests at roughly the
// configured rate (it must throttle, not just avoid hanging).
func TestPacing(t *testing.T) {
	l := New(20, 20) // 20 rps -> ~50ms between calls
	start := time.Now()
	for i := 0; i < 5; i++ {
		l.Wait("host")
	}
	elapsed := time.Since(start)
	// 5 calls at 20rps should take at least ~150ms (4 inter-call gaps of 50ms).
	if elapsed < 120*time.Millisecond {
		t.Fatalf("limiter did not throttle: 5 calls took %s", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("limiter over-throttled: 5 calls took %s", elapsed)
	}
}

func TestWAFSlowDown(t *testing.T) {
	l := New(1000, 1000)
	start := time.Now()
	l.SetWAFSlowDown(2)
	l.Wait("host")
	if time.Since(start) > 50*time.Millisecond {
		t.Fatalf("unexpected long wait")
	}
}

func TestSetRatesAppliesRuntimeWAFBudget(t *testing.T) {
	l := New(50, 30)
	l.SetWAFSlowDown(20)
	l.SetRates(3, 1)
	global, perHost, multiplier := l.Rates()
	if global != 3 || perHost != 1 || multiplier != 1 {
		t.Fatalf("unexpected runtime rates: global=%v host=%v multiplier=%v", global, perHost, multiplier)
	}
}

func TestWAFDecay(t *testing.T) {
	l := New(100, 100)
	l.SetWAFSlowDown(3.0)
	if l.wafMultiplier != 3.0 {
		t.Fatalf("expected WAF multiplier to be 3.0, got %f", l.wafMultiplier)
	}
	l.DecayWAFSlowDown(1.0)
	if l.wafMultiplier != 2.0 {
		t.Fatalf("expected WAF multiplier to be 2.0, got %f", l.wafMultiplier)
	}
	l.DecayWAFSlowDown(2.0)
	if l.wafMultiplier != 1.0 {
		t.Fatalf("expected WAF multiplier to decay only to 1.0, got %f", l.wafMultiplier)
	}
}
