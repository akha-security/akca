package observability

import (
	"encoding/json"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/akha-security/akca/engine/internal/storage"
)

type Collector struct {
	db       *storage.DB
	started  time.Time
	reqCount int64
	errCount int64
	backlog  int64
}

func NewCollector(db *storage.DB) *Collector {
	return &Collector{db: db, started: time.Now()}
}

type Snapshot struct {
	MemoryMB         float64            `json:"memory_mb"`
	Goroutines       int                `json:"goroutines"`
	QueueSizes       map[string]int     `json:"queue_sizes"`
	RequestRate      float64            `json:"request_rate"`
	ErrorRate        float64            `json:"error_rate"`
	DBWriteLatencyMs float64            `json:"db_write_latency_ms"`
	EventBacklog     int                `json:"event_backlog"`
	BrowserWorkers   int                `json:"browser_workers"`
	OASTStatus       string             `json:"oast_status"`
	ModuleRuntime    map[string]float64 `json:"module_runtime"`
	EngineStatus     string             `json:"engine_status"`
}

func (c *Collector) RecordRequest(err bool) {
	atomic.AddInt64(&c.reqCount, 1)
	if err {
		atomic.AddInt64(&c.errCount, 1)
	}
}

func (c *Collector) RequestCount() int64 {
	return atomic.LoadInt64(&c.reqCount)
}

func (c *Collector) SetBacklog(n int) {
	atomic.StoreInt64(&c.backlog, int64(n))
}

func (c *Collector) Capture(scanID string, moduleRuntime map[string]float64, oastStatus string, queueSizes map[string]int) (Snapshot, error) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	elapsed := time.Since(c.started).Seconds()
	if elapsed < 1 {
		elapsed = 1
	}
	rCount := atomic.LoadInt64(&c.reqCount)
	eCount := atomic.LoadInt64(&c.errCount)
	bLog := atomic.LoadInt64(&c.backlog)

	snap := Snapshot{
		MemoryMB:         float64(ms.Alloc) / (1024 * 1024),
		Goroutines:       runtime.NumGoroutine(),
		QueueSizes:       queueSizes,
		RequestRate:      float64(rCount) / elapsed,
		ErrorRate:        float64(eCount) / elapsed,
		DBWriteLatencyMs: c.measureDBLatency(),
		EventBacklog:     int(bLog),
		BrowserWorkers:   queueSizes["browser"],
		OASTStatus:       oastStatus,
		ModuleRuntime:    moduleRuntime,
		EngineStatus:     "healthy",
	}
	raw, _ := json.Marshal(snap)
	if err := c.db.SaveHealthSnapshot(scanID, string(raw)); err != nil {
		return snap, err
	}
	return snap, nil
}

func (c *Collector) measureDBLatency() float64 {
	start := time.Now()
	_ = c.db.Ping()
	return float64(time.Since(start).Microseconds()) / 1000
}
