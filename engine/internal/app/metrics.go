package app

import (
	"time"

	"github.com/akha-security/akca/engine/internal/events"
)

type metricBridge struct {
	agg *events.MetricAggregator
}

func newMetricBridge(scanID string, emit func(string, string, map[string]interface{}) error) *metricBridge {
	return &metricBridge{
		agg: events.NewMetricAggregator(scanID, 250*time.Millisecond, emit),
	}
}

func (m *metricBridge) Inc(key string, delta int) error {
	return m.agg.Inc(key, delta)
}

func (m *metricBridge) Flush() error {
	return m.agg.Flush()
}
