package session

import (
	"sync"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
)

type Status string

const (
	StatusIdle     Status = "idle"
	StatusRunning  Status = "running"
	StatusStopping Status = "stopping"
	StatusError    Status = "error"
)

type ScanSession struct {
	mu        sync.RWMutex
	ID        string            `json:"scan_id"`
	Status    Status            `json:"status"`
	Config    config.ScanConfig `json:"config"`
	StartedAt time.Time         `json:"started_at,omitempty"`
	UpdatedAt time.Time         `json:"updated_at,omitempty"`
	Phase     string            `json:"phase,omitempty"`
	Metrics   map[string]int    `json:"metrics,omitempty"`
}

func NewScanSession(cfg config.ScanConfig) *ScanSession {
	return &ScanSession{
		ID:      cfg.ScanID,
		Status:  StatusIdle,
		Config:  cfg,
		Metrics: map[string]int{},
	}
}

func (s *ScanSession) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Status = StatusRunning
	s.StartedAt = time.Now().UTC()
	s.UpdatedAt = s.StartedAt
}

func (s *ScanSession) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Status = StatusIdle
	s.UpdatedAt = time.Now().UTC()
}

// Stopping marks the session as winding down after a stop request, before the
// pipeline observes cancellation and transitions to idle.
func (s *ScanSession) Stopping() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Status = StatusStopping
	s.UpdatedAt = time.Now().UTC()
}

func (s *ScanSession) SetPhase(phase string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Phase = phase
	s.UpdatedAt = time.Now().UTC()
}

func (s *ScanSession) Increment(metric string, delta int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Metrics[metric] += delta
	s.UpdatedAt = time.Now().UTC()
}

func (s *ScanSession) SetMetric(metric string, val int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Metrics[metric] = val
	s.UpdatedAt = time.Now().UTC()
}

func (s *ScanSession) ApplyTrafficBudget(globalRate, perHostRate float64, maxConcurrency, perHostConcurrency int) config.ScanConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Config.GlobalRateLimit = globalRate
	s.Config.PerHostRateLimit = perHostRate
	s.Config.MaxConcurrency = maxConcurrency
	s.Config.PerHostConcurrency = perHostConcurrency
	s.UpdatedAt = time.Now().UTC()
	return s.Config
}

// UpdateConfig replaces the active scan configuration without racing readers
// that obtain a session snapshot. It is used when authentication is refreshed
// during a running scan.
func (s *ScanSession) UpdateConfig(cfg config.ScanConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Config = cfg
	s.UpdatedAt = time.Now().UTC()
}

// SessionState is a lock-free, serializable view of a ScanSession. It mirrors
// the JSON shape of ScanSession but omits the mutex so it can be safely copied
// and marshaled.
type SessionState struct {
	ID        string            `json:"scan_id"`
	Status    Status            `json:"status"`
	Config    config.ScanConfig `json:"config"`
	StartedAt time.Time         `json:"started_at,omitempty"`
	UpdatedAt time.Time         `json:"updated_at,omitempty"`
	Phase     string            `json:"phase,omitempty"`
	Metrics   map[string]int    `json:"metrics,omitempty"`
}

func (s *ScanSession) Snapshot() SessionState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	metrics := make(map[string]int, len(s.Metrics))
	for k, v := range s.Metrics {
		metrics[k] = v
	}
	return SessionState{
		ID:        s.ID,
		Status:    s.Status,
		Config:    s.Config,
		StartedAt: s.StartedAt,
		UpdatedAt: s.UpdatedAt,
		Phase:     s.Phase,
		Metrics:   metrics,
	}
}
