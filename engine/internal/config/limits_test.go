package config

import "testing"

func TestEffectiveMaxPagesUnlimitedUsesCeiling(t *testing.T) {
	cfg := DefaultScanConfig()
	cfg.MaxPages = 0
	cfg.ScanIntensity = "normal"
	if got := cfg.EffectiveMaxPages(); got != 1000 {
		t.Fatalf("expected default ceiling 1000, got %d", got)
	}
	cfg.ScanIntensity = "fast"
	if got := cfg.EffectiveMaxPages(); got != 2000 {
		t.Fatalf("expected fast ceiling 2000, got %d", got)
	}
}

func TestMaxEndpointsDefaultCeiling(t *testing.T) {
	cfg := DefaultScanConfig()
	if cfg.MaxEndpointsLimit() != defaultMaxEndpointsCeiling {
		t.Fatalf("expected %d, got %d", defaultMaxEndpointsCeiling, cfg.MaxEndpointsLimit())
	}
	cfg.MaxEndpoints = 10_000
	if cfg.MaxEndpointsLimit() != 10_000 {
		t.Fatal("expected custom max endpoints")
	}
}
