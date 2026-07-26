package session

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
)

func TestApplyTrafficBudget(t *testing.T) {
	s := NewScanSession(config.DefaultScanConfig())
	updated := s.ApplyTrafficBudget(3, 1, 4, 1)
	if updated.GlobalRateLimit != 3 || updated.PerHostRateLimit != 1 ||
		updated.MaxConcurrency != 4 || updated.PerHostConcurrency != 1 {
		t.Fatalf("unexpected session budget: %+v", updated)
	}
}
