package resilience

import (
	"encoding/json"
	"strings"

	"github.com/akha-security/akca/engine/internal/events"
)

// ParseEventLine mirrors the sidecar stdin parser: malformed lines are skipped.
func ParseEventLine(line string) (events.Event, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return events.Event{}, false
	}
	var evt events.Event
	if err := json.Unmarshal([]byte(line), &evt); err != nil {
		return events.Event{}, false
	}
	if evt.Type == "" || evt.TS == "" {
		return events.Event{}, false
	}
	return evt, true
}
