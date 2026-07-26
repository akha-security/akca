package events

import (
	"sync"
	"testing"
	"time"
)

func TestCompactMetricAggregation(t *testing.T) {
	var mu sync.Mutex
	var events []string
	emit := func(eventType, message string, payload map[string]interface{}) error {
		mu.Lock()
		events = append(events, eventType)
		mu.Unlock()
		return nil
	}

	agg := NewMetricAggregator("scan-1", 10*time.Millisecond, emit)
	_ = agg.Inc("waf_detected", 1)
	_ = agg.Inc("plugin_skipped", 3)
	time.Sleep(20 * time.Millisecond)
	_ = agg.Flush()

	mu.Lock()
	defer mu.Unlock()
	if len(events) == 0 {
		t.Fatal("expected dashboard_metric event")
	}
	if events[len(events)-1] != "dashboard_metric" {
		t.Fatalf("unexpected event type: %v", events)
	}
	counters := agg.Counters()
	if counters["plugin_skipped"] != 3 {
		t.Fatalf("counter mismatch: %v", counters)
	}
}
