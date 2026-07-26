package scheduler

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/storage"
)

type ScanStarter func(cfg config.ScanConfig) error

type Runner struct {
	mu       sync.Mutex
	db       *storage.DB
	start    ScanStarter
	limit    int
	running  int
	stopCh   chan struct{}
	stopOnce sync.Once
	tick     time.Duration
}

func NewRunner(db *storage.DB, start ScanStarter) *Runner {
	return &Runner{db: db, start: start, limit: 2, stopCh: make(chan struct{}), tick: 30 * time.Second}
}

func (r *Runner) Start(ctx context.Context) {
	t := time.NewTicker(r.tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stopCh:
			return
		case <-t.C:
			r.pollDue()
		}
	}
}

func (r *Runner) Stop() {
	r.stopOnce.Do(func() {
		close(r.stopCh)
	})
}

func (r *Runner) pollDue() {
	rows, err := r.db.ListDueScheduledScans(time.Now().UTC())
	if err != nil {
		return
	}
	for _, row := range rows {
		r.mu.Lock()
		if r.running >= r.limit {
			r.mu.Unlock()
			return
		}
		r.running++
		r.mu.Unlock()
		go r.execute(row)
	}
}

func (r *Runner) execute(row storage.ScheduledScanRow) {
	defer func() {
		r.mu.Lock()
		r.running--
		r.mu.Unlock()
	}()
	runID, _ := r.db.StartScheduledRun(row.ID)
	var cfg config.ScanConfig
	_ = json.Unmarshal([]byte(row.ConfigJSON), &cfg)
	if cfg.ScanID == "" {
		cfg.ScanID = "sched-" + row.ID + "-" + time.Now().Format("150405")
	}
	status := "completed"
	if r.start != nil {
		if err := r.start(cfg); err != nil {
			status = "failed"
		}
	}
	_ = r.db.FinishScheduledRun(runID, cfg.ScanID, status)
	_ = r.db.UpdateScheduledNextRun(row.ID, storage.NextRunEstimate(row.CronExpression))
}

func ParseCronPreview(expr string) string {
	return storage.CronHumanPreview(expr)
}
