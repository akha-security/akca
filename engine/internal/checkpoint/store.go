package checkpoint

import (
	"encoding/json"
	"time"

	"github.com/akha-security/akca/engine/internal/storage"
)

type State struct {
	Phase       string                 `json:"phase"`
	Completed   []string               `json:"completed_phases"`
	PhaseStatus map[string]string      `json:"phase_status,omitempty"`
	CrawlQueue  []string               `json:"crawl_queue,omitempty"`
	FuzzQueue   []string               `json:"fuzz_queue,omitempty"`
	ModuleState map[string]interface{} `json:"module_state,omitempty"`
	OASTPending []string               `json:"oast_pending,omitempty"`
	// Config holds the raw scan configuration so a scan can be fully resumed
	// (targets, scope, options) even after the engine process restarts.
	Config    json.RawMessage `json:"config,omitempty"`
	Version   int             `json:"version"`
	UpdatedAt string          `json:"updated_at"`
}

type Store struct {
	db *storage.DB
}

func NewStore(db *storage.DB) *Store {
	return &Store{db: db}
}

func (s *Store) Save(scanID string, st State) error {
	st.Version++
	st.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	raw, _ := json.Marshal(st)
	if err := s.db.SaveCheckpoint(scanID, string(raw)); err != nil {
		return err
	}
	return s.db.SaveResumeState(scanID, string(raw))
}

func (s *Store) Latest(scanID string) (State, bool, error) {
	rows, err := s.db.ListCheckpointRecords(scanID, 1)
	if err != nil {
		return State{}, false, err
	}
	if len(rows) == 0 {
		return State{}, false, nil
	}
	var st State
	if err := json.Unmarshal([]byte(rows[0].CheckpointJSON), &st); err != nil {
		return State{}, false, err
	}
	return st, true, nil
}

func (s *Store) ResumeFromPhase(st State) string {
	if st.Phase != "" {
		return st.Phase
	}
	if len(st.Completed) > 0 {
		return st.Completed[len(st.Completed)-1]
	}
	return "bootstrap"
}
