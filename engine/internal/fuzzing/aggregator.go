package fuzzing

import "sync"

type ResultAggregator struct {
	mu      sync.Mutex
	batch   []FuzzResult
	limit   int
	emit    EventSink
	scanID  string
}

func NewResultAggregator(scanID string, limit int, emit EventSink) *ResultAggregator {
	if limit <= 0 {
		limit = 50
	}
	return &ResultAggregator{scanID: scanID, limit: limit, emit: emit}
}

func (a *ResultAggregator) Add(result FuzzResult) error {
	a.mu.Lock()
	a.batch = append(a.batch, result)
	shouldFlush := len(a.batch) >= a.limit
	a.mu.Unlock()
	if shouldFlush {
		return a.Flush()
	}
	return nil
}

func (a *ResultAggregator) Flush() error {
	a.mu.Lock()
	batch := a.batch
	a.batch = nil
	a.mu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	counts := map[string]int{}
	for _, r := range batch {
		counts[r.Signal]++
	}
	return a.emit("fuzz_result_batch", "fuzz results", map[string]interface{}{
		"scan_id": a.scanID, "count": len(batch), "results": batch, "signals": counts,
	})
}
