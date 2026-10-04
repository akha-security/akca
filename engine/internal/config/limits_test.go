package config

import "testing"

func TestZeroCoverageLimitsAreUnlimited(t *testing.T) {
	cfg := ScanConfig{}
	if got := cfg.EffectiveMaxPages(); got != 0 {
		t.Fatalf("expected unlimited pages, got %d", got)
	}
	if got := cfg.MaxEndpointsLimit(); got != 0 {
		t.Fatalf("expected unlimited endpoints, got %d", got)
	}
	if got := cfg.ModuleTargetLimit(); got != 0 {
		t.Fatalf("expected unlimited module targets, got %d", got)
	}
	if got := cfg.ParameterDiscoveryEndpointLimit(); got != 0 {
		t.Fatalf("expected unlimited parameter discovery, got %d", got)
	}
	if got := cfg.ReflectionProfileLimit(); got != 0 {
		t.Fatalf("expected unlimited reflection profiles, got %d", got)
	}
}

func TestExplicitCoverageLimitsRemainHonored(t *testing.T) {
	cfg := DefaultScanConfig()
	cfg.MaxPages = 10_000
	cfg.MaxEndpoints = 10_000
	if cfg.EffectiveMaxPages() != 10_000 || cfg.ModuleTargetLimit() != 0 ||
		cfg.ParameterDiscoveryEndpointLimit() != 10_000 || cfg.ReflectionProfileLimit() != 0 ||
		cfg.MaxEndpointsLimit() != 10_000 {
		t.Fatalf("explicit limits were not preserved: %+v", cfg)
	}
}

func TestParameterDiscoveryBudgetsFollowIntensity(t *testing.T) {
	tests := []struct {
		intensity        string
		maxProbes        int
		wordlistCap      int
		maxHits          int
		maxTransferProbe int
	}{
		{intensity: "fast", maxProbes: 96, wordlistCap: 64, maxHits: 12, maxTransferProbe: 256},
		{intensity: "normal", maxProbes: 320, wordlistCap: 160, maxHits: 24, maxTransferProbe: 1000},
		{intensity: "stealth", maxProbes: 60, wordlistCap: 40, maxHits: 8, maxTransferProbe: 100},
	}
	for _, tt := range tests {
		cfg := DefaultScanConfig()
		cfg.ScanIntensity = tt.intensity
		if got := cfg.ParameterMaxProbes(); got != tt.maxProbes {
			t.Errorf("%s max probes=%d want %d", tt.intensity, got, tt.maxProbes)
		}
		if got := cfg.ParameterWordlistCap(); got != tt.wordlistCap {
			t.Errorf("%s wordlist cap=%d want %d", tt.intensity, got, tt.wordlistCap)
		}
		if got := cfg.ParameterMaxHits(); got != tt.maxHits {
			t.Errorf("%s max hits=%d want %d", tt.intensity, got, tt.maxHits)
		}
		if got := cfg.ParameterTransferMaxProbes(); got != tt.maxTransferProbe {
			t.Errorf("%s transfer probes=%d want %d", tt.intensity, got, tt.maxTransferProbe)
		}
	}
}

func TestFullCoverageParameterDiscoveryFollowsIntensity(t *testing.T) {
	cfg := DefaultScanConfig()
	if cfg.ScanIntensity != "normal" {
		t.Fatalf("default full scan intensity=%q, want normal", cfg.ScanIntensity)
	}
	if cfg.ParameterMaxProbes() != 320 || cfg.ParameterWordlistCap() != 160 || cfg.ParameterMaxHits() != 24 || cfg.ParameterTransferMaxProbes() != 1000 {
		t.Fatalf("full coverage parameter discovery must retain normal phase bounds: probes=%d words=%d hits=%d transfers=%d",
			cfg.ParameterMaxProbes(), cfg.ParameterWordlistCap(), cfg.ParameterMaxHits(), cfg.ParameterTransferMaxProbes())
	}
}

func TestFiniteFullScanBudgetPreservesModuleCapacity(t *testing.T) {
	cfg := DefaultScanConfig()
	cfg.RequestBudget = 4000
	if cfg.ParameterMaxProbes() != 320 || cfg.ParameterWordlistCap() != 160 || cfg.ParameterTransferMaxProbes() != 1000 {
		t.Fatalf("finite full scan must reserve capacity for vulnerability modules: probes=%d words=%d transfers=%d",
			cfg.ParameterMaxProbes(), cfg.ParameterWordlistCap(), cfg.ParameterTransferMaxProbes())
	}
}

func TestParameterDiscoveryWorkersHonorRuntimeConcurrencyCap(t *testing.T) {
	cfg := DefaultScanConfig()
	cfg.ScanIntensity = "fast"
	cfg.MaxConcurrency = 8
	if got := cfg.ParameterDiscoveryWorkers(); got != 8 {
		t.Fatalf("parameter workers=%d, want runtime WAF cap 8", got)
	}
}
