package events

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

type Event struct {
	Type    string                 `json:"type"`
	TS      string                 `json:"ts"`
	Message string                 `json:"message,omitempty"`
	Payload map[string]interface{} `json:"payload,omitempty"`
}

type Writer interface {
	WriteEvent(Event) error
}

type NDJSONWriter struct {
	out io.Writer
}

func NewNDJSONWriter(out io.Writer) *NDJSONWriter {
	return &NDJSONWriter{out: out}
}

func (w *NDJSONWriter) WriteEvent(e Event) error {
	if e.TS == "" {
		e.TS = time.Now().UTC().Format(time.RFC3339)
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = w.out.Write(append(b, '\n'))
	return err
}

// AsyncNDJSONWriter queues writes on a background goroutine so scan phases
// never block on a full stdout pipe when the desktop host reads slowly.
type AsyncNDJSONWriter struct {
	ch   chan []byte
	done chan struct{}
}

func NewAsyncNDJSONWriter(out io.Writer, buffer int) *AsyncNDJSONWriter {
	if buffer <= 0 {
		buffer = 512
	}
	w := &AsyncNDJSONWriter{
		ch:   make(chan []byte, buffer),
		done: make(chan struct{}),
	}
	go func() {
		defer close(w.done)
		for line := range w.ch {
			_, _ = out.Write(line)
		}
	}()
	return w
}

func (w *AsyncNDJSONWriter) WriteEvent(e Event) error {
	if e.TS == "" {
		e.TS = time.Now().UTC().Format(time.RFC3339)
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	w.ch <- append(b, '\n')
	return nil
}

func (w *AsyncNDJSONWriter) Close() error {
	close(w.ch)
	<-w.done
	return nil
}

type Batcher struct {
	mu        sync.Mutex
	maxSize   int
	flushDur  time.Duration
	pending   []Event
	writer    Writer
	stopCh    chan struct{}
	doneCh    chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func NewBatcher(writer Writer, maxSize int, flushDur time.Duration) *Batcher {
	if maxSize <= 0 {
		maxSize = 25
	}
	if flushDur <= 0 {
		flushDur = 100 * time.Millisecond
	}
	b := &Batcher{
		maxSize:  maxSize,
		flushDur: flushDur,
		writer:   writer,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
	go b.loop()
	return b
}

func (b *Batcher) Emit(e Event) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pending = append(b.pending, e)
	if shouldFlushImmediately(e.Type) || len(b.pending) >= b.maxSize {
		return b.flushLocked()
	}
	return nil
}

func shouldFlushImmediately(eventType string) bool {
	switch eventType {
	case "scan_started", "scan_finished", "scan_stopped", "scan_error", "scan_progress",
		"scan_snapshot", "phase_started", "phase_finished", "dashboard_metric",
		"crawler_started", "crawler_finished",
		"finding_detected", "finding_verified", "finding_confirmed", "finding_potential", "finding_candidate",
		"query_result", "oast_callback_received":
		return true
	default:
		return false
	}
}

func (b *Batcher) Flush() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.flushLocked()
}

func (b *Batcher) Close() error {
	b.closeOnce.Do(func() {
		close(b.stopCh)
		<-b.doneCh
		b.closeErr = b.Flush()
	})
	return b.closeErr
}

func (b *Batcher) PendingCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.pending)
}

func (b *Batcher) loop() {
	ticker := time.NewTicker(b.flushDur)
	defer ticker.Stop()
	defer close(b.doneCh)
	for {
		select {
		case <-ticker.C:
			_ = b.Flush()
		case <-b.stopCh:
			return
		}
	}
}

func (b *Batcher) flushLocked() error {
	if len(b.pending) == 0 {
		return nil
	}
	if len(b.pending) == 1 {
		err := b.writer.WriteEvent(b.pending[0])
		if err == nil {
			b.pending = b.pending[:0]
		}
		return err
	}
	payload := map[string]interface{}{
		"events": b.pending,
	}
	err := b.writer.WriteEvent(Event{
		Type:    "event_batch",
		TS:      time.Now().UTC().Format(time.RFC3339),
		Payload: payload,
	})
	if err == nil {
		b.pending = b.pending[:0]
	}
	return err
}
