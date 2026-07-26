package app

import (
	"github.com/akha-security/akca/engine/internal/fuzzing"
	"github.com/akha-security/akca/engine/internal/queue"
)

// hydrateQueue403FromDB rebuilds the auth bypass queue from persisted fuzz/crawl results.
func (e *Engine) hydrateQueue403FromDB(scanID string) {
	if e.queue403 != nil {
		return
	}
	entries, err := e.db.ListFuzzAuthBlockedURLs(scanID, 5000)
	if err != nil || len(entries) == 0 {
		entries, _ = e.db.ListAuthBlockedEndpoints(scanID, 5000)
	}
	if len(entries) == 0 {
		return
	}
	q := fuzzing.NewQueue403(10000)
	for _, ent := range entries {
		q.Enqueue(ent.URL, ent.Method)
	}
	e.queue403 = q
}

// ingestAuthBlockedFromCrawl enqueues 401/403 endpoints discovered during crawling.
func (e *Engine) ingestAuthBlockedFromCrawl(scanID string) {
	if e.queue403 == nil {
		e.queue403 = fuzzing.NewQueue403(10000)
	}
	entries, err := e.db.ListAuthBlockedEndpoints(scanID, 2000)
	if err != nil {
		return
	}
	for _, ent := range entries {
		e.queue403.Enqueue(ent.URL, ent.Method)
	}
}

// resetScanQueues clears per-scan queue state so a new or resumed scan does not
// inherit URLs from a previous run.
func (e *Engine) resetScanQueues() {
	e.queue403 = nil
	e.reqQueue = queue.NewRequestQueue()
}
