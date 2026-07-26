package resilience

import "testing"

func TestParseEventLine(t *testing.T) {
	if _, ok := ParseEventLine(`{"type":"log","ts":"2026-01-01T00:00:00Z"}`); !ok {
		t.Fatal("expected valid event")
	}
	if _, ok := ParseEventLine(`{broken`); ok {
		t.Fatal("expected invalid event")
	}
}
