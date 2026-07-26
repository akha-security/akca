package safemutation

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

type Risk string

const (
	ReadOnly               Risk = "read_only"
	ReversibleWrite        Risk = "reversible_write"
	PotentiallyDestructive Risk = "potentially_destructive"
	FinancialIrreversible  Risk = "financial_irreversible"
)

type Policy struct {
	AllowReadOnly         bool `json:"allow_read_only"`
	AllowReversibleWrites bool `json:"allow_reversible_writes"`
	AllowDestructive      bool `json:"allow_destructive"`
	AllowFinancial        bool `json:"allow_financial"`
	RequireCleanup        bool `json:"require_cleanup"`
}

func DefaultPolicy() Policy {
	return Policy{AllowReadOnly: true, AllowReversibleWrites: true, RequireCleanup: true}
}

type Operation struct {
	ID             string `json:"id"`
	Risk           Risk   `json:"risk"`
	ResourceID     string `json:"resource_id,omitempty"`
	CleanupDefined bool   `json:"cleanup_defined"`
}

type Transaction struct {
	ID              string    `json:"id"`
	OperationID     string    `json:"operation_id"`
	ResourceID      string    `json:"resource_id,omitempty"`
	Canary          string    `json:"canary"`
	StateBeforeHash string    `json:"state_before_hash,omitempty"`
	StateAfterHash  string    `json:"state_after_hash,omitempty"`
	CleanupRequired bool      `json:"cleanup_required"`
	CleanupComplete bool      `json:"cleanup_complete"`
	StartedAt       time.Time `json:"started_at"`
	FinishedAt      time.Time `json:"finished_at,omitempty"`
}

type FailureSink func(Transaction, error)

type Guard struct {
	mu              sync.Mutex
	policy          Policy
	active          map[string]Transaction
	activeResources map[string]string
	touched         map[string]struct{}
	onFailure       FailureSink
}

func NewGuard(policy Policy) *Guard {
	return NewGuardWithFailureSink(policy, nil)
}

func NewGuardWithFailureSink(policy Policy, sink FailureSink) *Guard {
	return &Guard{
		policy: policy, active: make(map[string]Transaction),
		activeResources: make(map[string]string), touched: make(map[string]struct{}),
		onFailure: sink,
	}
}

func (g *Guard) Begin(operation Operation, beforeHash string) (Transaction, error) {
	if err := g.authorize(operation); err != nil {
		return Transaction{}, err
	}
	resourceID := strings.TrimSpace(operation.ResourceID)
	if operation.Risk != ReadOnly {
		if strings.TrimSpace(beforeHash) == "" {
			return Transaction{}, fmt.Errorf("state snapshot is required before mutation")
		}
		if resourceID == "" {
			return Transaction{}, fmt.Errorf("mutation resource ID is required")
		}
	}
	tx := Transaction{
		ID: randomID(), OperationID: operation.ID, Canary: "akca-" + randomID(),
		ResourceID: resourceID, StateBeforeHash: beforeHash,
		CleanupRequired: operation.Risk != ReadOnly,
		StartedAt:       time.Now().UTC(),
	}
	g.mu.Lock()
	if owner, exists := g.activeResources[resourceID]; resourceID != "" && exists {
		g.mu.Unlock()
		return Transaction{}, fmt.Errorf("resource %s is already mutated by transaction %s", resourceID, owner)
	}
	if _, exists := g.touched[resourceID]; resourceID != "" && exists {
		g.mu.Unlock()
		return Transaction{}, fmt.Errorf("resource %s was already mutated in this run", resourceID)
	}
	g.active[tx.ID] = tx
	if resourceID != "" {
		g.activeResources[resourceID] = tx.ID
	}
	g.mu.Unlock()
	return tx, nil
}

func (g *Guard) Finish(id, afterHash string, cleanupComplete bool) (Transaction, error) {
	g.mu.Lock()
	tx, ok := g.active[id]
	if !ok {
		g.mu.Unlock()
		return Transaction{}, fmt.Errorf("unknown mutation transaction")
	}
	tx.StateAfterHash = afterHash
	tx.CleanupComplete = cleanupComplete
	tx.FinishedAt = time.Now().UTC()
	delete(g.active, id)
	delete(g.activeResources, tx.ResourceID)
	if tx.ResourceID != "" {
		g.touched[tx.ResourceID] = struct{}{}
	}
	g.mu.Unlock()
	if tx.CleanupRequired && !cleanupComplete {
		err := fmt.Errorf("cleanup failed for mutation %s", tx.OperationID)
		if g.onFailure != nil {
			g.onFailure(tx, err)
		}
		return tx, err
	}
	return tx, nil
}

func (g *Guard) authorize(operation Operation) error {
	switch operation.Risk {
	case ReadOnly:
		if !g.policy.AllowReadOnly {
			return fmt.Errorf("read-only operation disabled")
		}
	case ReversibleWrite:
		if !g.policy.AllowReversibleWrites {
			return fmt.Errorf("reversible writes disabled")
		}
		if g.policy.RequireCleanup && !operation.CleanupDefined {
			return fmt.Errorf("reversible write requires cleanup")
		}
	case PotentiallyDestructive:
		if !g.policy.AllowDestructive {
			return fmt.Errorf("destructive operation requires explicit authorization")
		}
	case FinancialIrreversible:
		if !g.policy.AllowFinancial {
			return fmt.Errorf("financial operation requires explicit authorization")
		}
	default:
		return fmt.Errorf("unknown operation risk %q", operation.Risk)
	}
	if strings.TrimSpace(operation.ID) == "" {
		return fmt.Errorf("operation ID is required")
	}
	return nil
}

func randomID() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(raw[:])
}
