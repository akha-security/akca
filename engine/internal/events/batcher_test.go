package events

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

type memWriter struct {
	buf bytes.Buffer
}

type failingWriter struct{}

func (failingWriter) WriteEvent(Event) error { return errors.New("write failed") }

func TestBatcherRetainsEventsAfterWriteFailure(t *testing.T) {
	b := NewBatcher(failingWriter{}, 1, time.Hour)
	defer b.Close()
	if err := b.Emit(Event{Type: "log"}); err == nil {
		t.Fatal("expected write failure")
	}
	if b.PendingCount() != 1 {
		t.Fatalf("pending events = %d, want 1", b.PendingCount())
	}
}

func (m *memWriter) WriteEvent(e Event) error {
	b, err := jsonMarshal(e)
	if err != nil {
		return err
	}
	_, err = m.buf.Write(append(b, '\n'))
	return err
}

func jsonMarshal(e Event) ([]byte, error) {
	return []byte(`{"type":"` + e.Type + `"}`), nil
}

func TestBatcherFlushesOnSize(t *testing.T) {
	w := &memWriter{}
	b := NewBatcher(w, 3, time.Second)
	defer b.Close()

	for i := 0; i < 3; i++ {
		if err := b.Emit(Event{Type: "log"}); err != nil {
			t.Fatal(err)
		}
	}
	if b.PendingCount() != 0 {
		t.Fatalf("expected pending flushed")
	}
	if !strings.Contains(w.buf.String(), "event_batch") {
		t.Fatalf("expected batch event, got %q", w.buf.String())
	}
}

func TestBatcherBoundedPending(t *testing.T) {
	w := &memWriter{}
	b := NewBatcher(w, 2, 10*time.Second)
	defer b.Close()
	_ = b.Emit(Event{Type: "log"})
	if b.PendingCount() != 1 {
		t.Fatalf("expected one pending event")
	}
}

func TestFindingEventsFlushImmediately(t *testing.T) {
	w := &memWriter{}
	b := NewBatcher(w, 100, time.Hour)
	defer b.Close()

	if err := b.Emit(Event{Type: "finding_detected"}); err != nil {
		t.Fatal(err)
	}
	if b.PendingCount() != 0 {
		t.Fatal("finding_detected must not wait in the event batch")
	}
	if !strings.Contains(w.buf.String(), "finding_detected") {
		t.Fatalf("finding event was not delivered immediately: %q", w.buf.String())
	}
}
