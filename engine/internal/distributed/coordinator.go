package distributed

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/akha-security/akca/engine/internal/storage"
)

type JobType string

const (
	JobCrawl            JobType = "crawl"
	JobBrowser          JobType = "browser"
	JobAPIImport        JobType = "api_import"
	JobInjection        JobType = "injection"
	JobOASTWait         JobType = "oast_wait"
	JobStatefulWorkflow JobType = "stateful_workflow"
	JobReport           JobType = "report"
)

const (
	StatusQueued    = "queued"
	StatusLeased    = "leased"
	StatusRunning   = "running"
	StatusCompleted = "completed"
	StatusFailed    = "failed"
	StatusCanceled  = "canceled"
)

var (
	ErrNoJob      = errors.New("no dispatchable job")
	ErrLeaseLost  = errors.New("worker lease lost")
	ErrCanceled   = errors.New("job canceled")
	ErrOutOfScope = errors.New("job target is outside its immutable scope")
)

type Spec struct {
	ID             string          `json:"id,omitempty"`
	IdempotencyKey string          `json:"idempotency_key"`
	Type           JobType         `json:"job_type"`
	ScanID         string          `json:"scan_id"`
	Payload        json.RawMessage `json:"payload"`
	Scope          []string        `json:"scope"`
	RateLimitRPS   float64         `json:"rate_limit_rps"`
	Priority       int             `json:"priority,omitempty"`
	MaxAttempts    int             `json:"max_attempts,omitempty"`
}

type Job struct {
	Spec
	Status          string          `json:"status"`
	OwnerID         string          `json:"owner_id,omitempty"`
	LeaseUntil      string          `json:"lease_until,omitempty"`
	Checkpoint      json.RawMessage `json:"checkpoint,omitempty"`
	Attempts        int             `json:"attempts"`
	CancelRequested bool            `json:"cancel_requested"`
	LastError       string          `json:"last_error,omitempty"`
	CreatedAt       string          `json:"created_at"`
	UpdatedAt       string          `json:"updated_at"`
}

type Coordinator struct {
	db            *storage.DB
	leaseDuration time.Duration
	now           func() time.Time
}

func NewCoordinator(db *storage.DB, leaseDuration time.Duration) *Coordinator {
	if leaseDuration <= 0 {
		leaseDuration = 30 * time.Second
	}
	return &Coordinator{db: db, leaseDuration: leaseDuration, now: time.Now}
}

func (c *Coordinator) Enqueue(spec Spec) (string, error) {
	if c.db == nil {
		return "", errors.New("distributed job storage is unavailable")
	}
	if !validJobType(spec.Type) || strings.TrimSpace(spec.IdempotencyKey) == "" ||
		strings.TrimSpace(spec.ScanID) == "" || !json.Valid(spec.Payload) {
		return "", errors.New("job type, idempotency key, scan id and valid JSON payload are required")
	}
	if spec.Type != JobReport && (len(spec.Scope) == 0 || spec.RateLimitRPS <= 0) {
		return "", errors.New("network jobs require immutable scope and a positive rate limit")
	}
	scopeJSON, err := json.Marshal(spec.Scope)
	if err != nil {
		return "", err
	}
	if spec.ID == "" {
		spec.ID, err = randomID()
		if err != nil {
			return "", err
		}
	}
	if spec.MaxAttempts <= 0 {
		spec.MaxAttempts = 3
	}
	result, err := c.db.Conn().Exec(`
INSERT OR IGNORE INTO distributed_jobs
  (id, idempotency_key, job_type, scan_id, payload_json, scope_json, rate_limit_rps,
   priority, status, max_attempts)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		spec.ID, spec.IdempotencyKey, spec.Type, spec.ScanID, string(spec.Payload), string(scopeJSON),
		spec.RateLimitRPS, spec.Priority, StatusQueued, spec.MaxAttempts)
	if err != nil {
		return "", err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return "", err
	}
	if inserted == 1 {
		return spec.ID, nil
	}
	var existing string
	if err := c.db.Conn().QueryRow(
		`SELECT id FROM distributed_jobs WHERE idempotency_key = ?`, spec.IdempotencyKey).Scan(&existing); err != nil {
		return "", err
	}
	return existing, nil
}

func (c *Coordinator) Lease(ownerID string) (Job, error) {
	if strings.TrimSpace(ownerID) == "" {
		return Job{}, errors.New("worker owner id is required")
	}
	tx, err := c.db.Conn().Begin()
	if err != nil {
		return Job{}, err
	}
	defer func() { _ = tx.Rollback() }()
	now := c.now().UTC()
	nowText := now.Format(time.RFC3339Nano)
	if _, err := tx.Exec(`
UPDATE distributed_jobs
SET status = CASE
      WHEN cancel_requested = 1 THEN ?
      WHEN attempts >= max_attempts THEN ?
      ELSE ?
    END,
    last_error = CASE
      WHEN cancel_requested = 0 AND attempts >= max_attempts THEN 'worker lease expired after final attempt'
      ELSE last_error
    END,
    owner_id = NULL, lease_until = NULL, updated_at = ?
WHERE status IN (?, ?) AND lease_until < ?`,
		StatusCanceled, StatusFailed, StatusQueued, nowText, StatusLeased, StatusRunning, nowText); err != nil {
		return Job{}, err
	}
	var id string
	err = tx.QueryRow(`
SELECT id FROM distributed_jobs
WHERE status = ? AND cancel_requested = 0 AND attempts < max_attempts
ORDER BY priority DESC, created_at, id LIMIT 1`, StatusQueued).Scan(&id)
	if err == sql.ErrNoRows {
		return Job{}, ErrNoJob
	}
	if err != nil {
		return Job{}, err
	}
	leaseUntil := now.Add(c.leaseDuration).Format(time.RFC3339Nano)
	result, err := tx.Exec(`
UPDATE distributed_jobs
SET status = ?, owner_id = ?, lease_until = ?, attempts = attempts + 1, updated_at = ?
WHERE id = ? AND status = ? AND cancel_requested = 0`,
		StatusLeased, ownerID, leaseUntil, nowText, id, StatusQueued)
	if err != nil {
		return Job{}, err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return Job{}, ErrNoJob
	}
	job, err := scanJob(tx.QueryRow(jobSelect+` WHERE id = ?`, id))
	if err != nil {
		return Job{}, err
	}
	if err := tx.Commit(); err != nil {
		return Job{}, err
	}
	return job, nil
}

func (c *Coordinator) Heartbeat(jobID, ownerID string) error {
	now := c.now().UTC()
	result, err := c.db.Conn().Exec(`
UPDATE distributed_jobs
SET status = ?, lease_until = ?, updated_at = ?
WHERE id = ? AND owner_id = ? AND status IN (?, ?) AND cancel_requested = 0`,
		StatusRunning, now.Add(c.leaseDuration).Format(time.RFC3339Nano), now.Format(time.RFC3339Nano),
		jobID, ownerID, StatusLeased, StatusRunning)
	if err != nil {
		return err
	}
	return affectedOrState(c.db.Conn(), result, jobID)
}

func (c *Coordinator) Checkpoint(jobID, ownerID string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	now := c.now().UTC()
	result, err := c.db.Conn().Exec(`
UPDATE distributed_jobs
SET status = ?, checkpoint_json = ?, lease_until = ?, updated_at = ?
WHERE id = ? AND owner_id = ? AND status IN (?, ?) AND cancel_requested = 0`,
		StatusRunning, string(raw), now.Add(c.leaseDuration).Format(time.RFC3339Nano),
		now.Format(time.RFC3339Nano), jobID, ownerID, StatusLeased, StatusRunning)
	if err != nil {
		return err
	}
	return affectedOrState(c.db.Conn(), result, jobID)
}

func (c *Coordinator) Cancel(jobID string) error {
	result, err := c.db.Conn().Exec(`
UPDATE distributed_jobs
SET cancel_requested = 1,
    status = CASE WHEN status = ? THEN ? ELSE status END,
    updated_at = ?
WHERE id = ? AND status NOT IN (?, ?, ?)`,
		StatusQueued, StatusCanceled, c.now().UTC().Format(time.RFC3339Nano), jobID,
		StatusCompleted, StatusFailed, StatusCanceled)
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return fmt.Errorf("job %q is missing or terminal", jobID)
	}
	return nil
}

func (c *Coordinator) Complete(jobID, ownerID string) error {
	result, err := c.db.Conn().Exec(`
UPDATE distributed_jobs
SET status = CASE WHEN cancel_requested = 1 THEN ? ELSE ? END,
    owner_id = NULL, lease_until = NULL, updated_at = ?
WHERE id = ? AND owner_id = ? AND status IN (?, ?)`,
		StatusCanceled, StatusCompleted, c.now().UTC().Format(time.RFC3339Nano),
		jobID, ownerID, StatusLeased, StatusRunning)
	if err != nil {
		return err
	}
	return affectedOrState(c.db.Conn(), result, jobID)
}

func (c *Coordinator) Fail(jobID, ownerID string, cause error) error {
	message := ""
	if cause != nil {
		message = cause.Error()
	}
	result, err := c.db.Conn().Exec(`
UPDATE distributed_jobs
SET status = CASE
      WHEN cancel_requested = 1 THEN ?
      WHEN attempts < max_attempts THEN ?
      ELSE ?
    END,
    owner_id = NULL, lease_until = NULL, last_error = ?, updated_at = ?
WHERE id = ? AND owner_id = ? AND status IN (?, ?)`,
		StatusCanceled, StatusQueued, StatusFailed, message, c.now().UTC().Format(time.RFC3339Nano),
		jobID, ownerID, StatusLeased, StatusRunning)
	if err != nil {
		return err
	}
	return affectedOrState(c.db.Conn(), result, jobID)
}

func (c *Coordinator) Get(jobID string) (Job, error) {
	return scanJob(c.db.Conn().QueryRow(jobSelect+` WHERE id = ?`, jobID))
}

const jobSelect = `
SELECT id, idempotency_key, job_type, scan_id, payload_json, scope_json, rate_limit_rps,
       priority, status, COALESCE(owner_id,''), COALESCE(lease_until,''),
       COALESCE(checkpoint_json,''), attempts, max_attempts, cancel_requested,
       COALESCE(last_error,''), created_at, updated_at
FROM distributed_jobs`

type scanner interface {
	Scan(dest ...any) error
}

func scanJob(row scanner) (Job, error) {
	var job Job
	var payload, scope, checkpoint string
	var canceled int
	err := row.Scan(&job.ID, &job.IdempotencyKey, &job.Type, &job.ScanID, &payload, &scope,
		&job.RateLimitRPS, &job.Priority, &job.Status, &job.OwnerID, &job.LeaseUntil,
		&checkpoint, &job.Attempts, &job.MaxAttempts, &canceled, &job.LastError,
		&job.CreatedAt, &job.UpdatedAt)
	if err != nil {
		return Job{}, err
	}
	job.Payload = json.RawMessage(payload)
	if checkpoint != "" {
		job.Checkpoint = json.RawMessage(checkpoint)
	}
	if err := json.Unmarshal([]byte(scope), &job.Scope); err != nil {
		return Job{}, err
	}
	job.CancelRequested = canceled == 1
	return job, nil
}

func affectedOrState(db *sql.DB, result sql.Result, jobID string) error {
	if rows, _ := result.RowsAffected(); rows == 1 {
		return nil
	}
	var canceled int
	err := db.QueryRow(`SELECT cancel_requested FROM distributed_jobs WHERE id = ?`, jobID).Scan(&canceled)
	if err == nil && canceled == 1 {
		return ErrCanceled
	}
	return ErrLeaseLost
}

func validJobType(kind JobType) bool {
	switch kind {
	case JobCrawl, JobBrowser, JobAPIImport, JobInjection, JobOASTWait, JobStatefulWorkflow, JobReport:
		return true
	default:
		return false
	}
}

func randomID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "job-" + hex.EncodeToString(raw[:]), nil
}

type Controls struct {
	coordinator *Coordinator
	job         Job
	ownerID     string
	mu          sync.Mutex
	lastRequest time.Time
}

func (c *Controls) AuthorizeURL(rawURL string) error {
	target, err := url.Parse(rawURL)
	if err != nil || target.Scheme == "" || target.Hostname() == "" {
		return ErrOutOfScope
	}
	for _, rawAllowed := range c.job.Scope {
		allowed := strings.TrimSpace(rawAllowed)
		if strings.HasPrefix(allowed, "*.") {
			suffix := strings.TrimPrefix(strings.ToLower(allowed), "*.")
			host := strings.ToLower(target.Hostname())
			if host != suffix && strings.HasSuffix(host, "."+suffix) {
				return nil
			}
			continue
		}
		parsed, parseErr := url.Parse(allowed)
		if parseErr == nil && parsed.Hostname() != "" {
			sameOrigin := strings.EqualFold(parsed.Scheme, target.Scheme) &&
				strings.EqualFold(parsed.Host, target.Host)
			if sameOrigin && (parsed.Path == "" || parsed.Path == "/" ||
				strings.HasPrefix(target.EscapedPath(), parsed.EscapedPath())) {
				return nil
			}
			continue
		}
		if strings.EqualFold(target.Hostname(), allowed) {
			return nil
		}
	}
	return ErrOutOfScope
}

func (c *Controls) Wait(ctx context.Context) error {
	if c.job.RateLimitRPS <= 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	interval := time.Duration(float64(time.Second) / c.job.RateLimitRPS)
	wait := time.Until(c.lastRequest.Add(interval))
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	c.lastRequest = time.Now()
	return nil
}

func (c *Controls) Checkpoint(value any) error {
	return c.coordinator.Checkpoint(c.job.ID, c.ownerID, value)
}

type Handler func(context.Context, Job, *Controls) error

type Worker struct {
	ID          string
	Coordinator *Coordinator
	Handlers    map[JobType]Handler
}

func (w *Worker) RunOnce(ctx context.Context) error {
	if w.Coordinator == nil || strings.TrimSpace(w.ID) == "" {
		return errors.New("worker id and coordinator are required")
	}
	job, err := w.Coordinator.Lease(w.ID)
	if err != nil {
		return err
	}
	handler := w.Handlers[job.Type]
	if handler == nil {
		cause := fmt.Errorf("no handler for %s", job.Type)
		if err := w.Coordinator.Fail(job.ID, w.ID, cause); err != nil {
			return err
		}
		return cause
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		interval := w.Coordinator.leaseDuration / 3
		if interval < 50*time.Millisecond {
			interval = 50 * time.Millisecond
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-runCtx.Done():
				return
			case <-ticker.C:
				if heartbeatErr := w.Coordinator.Heartbeat(job.ID, w.ID); heartbeatErr != nil {
					cancel()
					return
				}
			}
		}
	}()
	controls := &Controls{coordinator: w.Coordinator, job: job, ownerID: w.ID}
	handlerErr := handler(runCtx, job, controls)
	close(done)
	<-monitorDone
	if handlerErr != nil {
		if failErr := w.Coordinator.Fail(job.ID, w.ID, handlerErr); failErr != nil {
			return failErr
		}
		return handlerErr
	}
	return w.Coordinator.Complete(job.ID, w.ID)
}
