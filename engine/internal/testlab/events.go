package testlab

import (
	"encoding/json"
	"strings"
	"sync"

	"github.com/akha-security/akca/engine/internal/events"
)

// EventCollector records structured engine events for integration assertions.
type EventCollector struct {
	mu     sync.Mutex
	events []events.Event
	types  map[string]int
}

func NewEventCollector() *EventCollector {
	return &EventCollector{types: map[string]int{}}
}

func (c *EventCollector) WriteEvent(e events.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
	c.types[e.Type]++
	if e.Type == "event_batch" && e.Payload != nil {
		if raw, ok := e.Payload["events"].([]events.Event); ok {
			for _, nested := range raw {
				c.types[nested.Type]++
			}
		}
	}
	return nil
}

func (c *EventCollector) HasType(eventType string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.types[eventType] > 0
}

func (c *EventCollector) Count(eventType string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.types[eventType]
}

func (c *EventCollector) Types() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]int, len(c.types))
	for k, v := range c.types {
		out[k] = v
	}
	return out
}

func (c *EventCollector) Events() []events.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]events.Event, len(c.events))
	copy(out, c.events)
	return out
}

// AssertStructuredBatches ensures UI-facing events are batched, not unbounded single payloads.
func (c *EventCollector) AssertStructuredBatches() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.events) == 0 {
		return false
	}
	batches := 0
	for _, e := range c.events {
		if e.Type == "event_batch" {
			batches++
			if raw, ok := e.Payload["events"]; ok {
				switch v := raw.(type) {
				case []events.Event:
					if len(v) > 200 {
						return false
					}
				case []interface{}:
					if len(v) > 200 {
						return false
					}
				}
			}
		}
	}
	return batches > 0
}

func (c *EventCollector) PayloadContains(substr string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.events {
		if strings.Contains(e.Message, substr) {
			return true
		}
		b, _ := json.Marshal(e.Payload)
		if strings.Contains(string(b), substr) {
			return true
		}
	}
	return false
}
