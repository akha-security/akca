package config

import "testing"

func TestURLBudgetConfig(t *testing.T) {
	cfg := DefaultScanConfig()
	cfg.RequestsPerTarget = 100
	if got := cfg.EffectiveRequestBudget(3); got != 300 {
		t.Fatalf("derived=%d", got)
	}
	cfg.RequestBudget = 17
	if got := cfg.EffectiveRequestBudget(3); got != 17 {
		t.Fatalf("explicit cap lost: %d", got)
	}
	cfg.RequestBudget = 0
	cfg.RequestsPerTarget = int(^uint(0) >> 1)
	if got := cfg.EffectiveRequestBudget(3); got != int(^uint(0)>>1) {
		t.Fatalf("overflow: %d", got)
	}
	cfg.RequestsPerTarget = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("negative URL budget accepted")
	}
}
