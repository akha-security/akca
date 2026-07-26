package browserpool

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/akha-security/akca/engine/internal/storage"
)

type TaskType string

const (
	TaskSPACrawl     TaskType = "spa_crawl"
	TaskDOMXSS       TaskType = "dom_xss"
	TaskLoginCapture TaskType = "login_capture"
	TaskJSHeavy      TaskType = "js_heavy"
)

type Task struct {
	ID       string                 `json:"id"`
	Type     TaskType               `json:"type"`
	URL      string                 `json:"url"`
	Context  string                 `json:"context"`
	Timeout  time.Duration          `json:"timeout"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

type TaskHandler func(context.Context, Task) error

type Worker struct {
	ID            string    `json:"id"`
	Status        string    `json:"status"`
	ActiveTab     string    `json:"active_tab,omitempty"`
	Completed     int       `json:"completed"`
	Failed        int       `json:"failed"`
	LastError     string    `json:"last_error,omitempty"`
	RestartCount  int       `json:"restart_count"`
	LastRestartAt string    `json:"last_restart_at,omitempty"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type Pool struct {
	mu          sync.Mutex
	db          *storage.DB
	size        int
	queue       []Task
	workers     map[string]*Worker
	stopCh      chan struct{}
	pageFetcher PageFetcher
	handlers    map[TaskType]TaskHandler
}

func NewPool(db *storage.DB, size int) *Pool {
	if size <= 0 {
		size = 2
	}
	p := &Pool{
		db:       db,
		size:     size,
		workers:  map[string]*Worker{},
		stopCh:   make(chan struct{}),
		handlers: make(map[TaskType]TaskHandler),
	}
	for i := 0; i < size; i++ {
		id := fmtWorkerID(i)
		p.workers[id] = &Worker{ID: id, Status: "idle", UpdatedAt: time.Now().UTC()}
	}
	return p
}

func fmtWorkerID(i int) string {
	return fmt.Sprintf("worker-%d", i)
}

func (p *Pool) Start(ctx context.Context) {
	for id := range p.workers {
		go p.runWorker(ctx, id)
	}
}

func (p *Pool) Enqueue(task Task) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if task.Timeout == 0 {
		task.Timeout = 30 * time.Second
	}
	p.queue = append(p.queue, task)
}

func (p *Pool) runWorker(ctx context.Context, id string) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopCh:
			return
		default:
		}
		task, ok := p.dequeue(id)
		if !ok {
			time.Sleep(100 * time.Millisecond)
			p.persistHealth(id)
			continue
		}
		p.execute(ctx, id, task)
	}
}

func (p *Pool) dequeue(workerID string) (Task, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.queue) == 0 {
		return Task{}, false
	}
	task := p.queue[0]
	p.queue = p.queue[1:]
	if w := p.workers[workerID]; w != nil {
		w.Status = "busy"
		w.ActiveTab = task.URL
		w.UpdatedAt = time.Now().UTC()
	}
	return task, true
}

func (p *Pool) SetPageFetcher(fetcher PageFetcher) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pageFetcher = fetcher
}

// SetTaskHandler registers real execution for specialized browser work. Tasks
// without a renderer/fetcher/handler fail visibly instead of being counted as
// successful simulated work.
func (p *Pool) SetTaskHandler(taskType TaskType, handler TaskHandler) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if handler == nil {
		delete(p.handlers, taskType)
		return
	}
	p.handlers[taskType] = handler
}

func (p *Pool) execute(ctx context.Context, id string, task Task) {
	taskCtx, cancel := context.WithTimeout(ctx, task.Timeout)
	defer cancel()
	p.mu.Lock()
	if w := p.workers[id]; w != nil {
		w.Status = "running"
		w.UpdatedAt = time.Now().UTC()
	}
	p.mu.Unlock()

	err := p.executeTask(taskCtx, task)

	p.mu.Lock()
	w := p.workers[id]
	if w == nil {
		p.mu.Unlock()
		return
	}
	if err != nil {
		w.Failed++
		w.LastError = err.Error()
		if w.Failed%3 == 0 {
			w.RestartCount++
			w.LastRestartAt = time.Now().UTC().Format(time.RFC3339)
			w.Status = "restarting"
		} else {
			w.Status = "error"
		}
	} else {
		w.Completed++
		w.Status = "idle"
		w.LastError = ""
	}
	w.UpdatedAt = time.Now().UTC()
	p.mu.Unlock()
	p.persistHealth(id)
}

func (p *Pool) executeTask(ctx context.Context, task Task) error {
	p.mu.Lock()
	handler := p.handlers[task.Type]
	fetcher := p.pageFetcher
	p.mu.Unlock()
	if handler != nil {
		return handler(ctx, task)
	}
	switch task.Type {
	case TaskSPACrawl, TaskDOMXSS, TaskJSHeavy:
		if fetcher == nil {
			return fmt.Errorf("browser task %s has no page fetcher", task.Type)
		}
		_, err := fetcher(ctx, task.URL)
		return err
	case TaskLoginCapture:
		return fmt.Errorf("browser task %s requires a registered login handler", task.Type)
	default:
		return fmt.Errorf("unsupported browser task type %q", task.Type)
	}
}

func (p *Pool) persistHealth(id string) {
	p.mu.Lock()
	w := p.workers[id]
	if w == nil {
		p.mu.Unlock()
		return
	}
	snapshot := *w
	p.mu.Unlock()
	if p.db == nil {
		return
	}
	raw, _ := json.Marshal(snapshot)
	_ = p.db.UpsertBrowserWorker(id, snapshot.Status, string(raw))
}

func (p *Pool) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	select {
	case <-p.stopCh:
		return
	default:
		close(p.stopCh)
	}
}

func (p *Pool) Stats() map[string]int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return map[string]int{"queued": len(p.queue), "workers": len(p.workers)}
}
