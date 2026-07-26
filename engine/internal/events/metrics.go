package events

import (
	"sync"
	"time"
)

// MetricAggregator emits compact dashboard metric events suitable for large scans.
type MetricAggregator struct {
	mu       sync.Mutex
	scanID   string
	counters map[string]int
	emitter  func(eventType, message string, payload map[string]interface{}) error
	lastEmit time.Time
	interval time.Duration
}

func NewMetricAggregator(scanID string, interval time.Duration, emit func(string, string, map[string]interface{}) error) *MetricAggregator {
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	return &MetricAggregator{
		scanID:   scanID,
		counters: map[string]int{},
		emitter:  emit,
		interval: interval,
	}
}

func (m *MetricAggregator) Inc(key string, delta int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counters[key] += delta
	if time.Since(m.lastEmit) >= m.interval {
		return m.flushLocked()
	}
	return nil
}

func (m *MetricAggregator) Flush() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.flushLocked()
}

func (m *MetricAggregator) Counters() map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]int, len(m.counters))
	for k, v := range m.counters {
		out[k] = v
	}
	return out
}

func (m *MetricAggregator) flushLocked() error {
	if len(m.counters) == 0 {
		return nil
	}
	payload := map[string]interface{}{
		"scan_id":  m.scanID,
		"counters": cloneCounters(m.counters),
	}
	m.lastEmit = time.Now().UTC()
	return m.emitter("dashboard_metric", "compact metrics", payload)
}

func cloneCounters(in map[string]int) map[string]int {
	out := make(map[string]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
