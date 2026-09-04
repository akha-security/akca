package config

import (
	"reflect"
	"sort"
	"testing"
)

func TestFindMode(t *testing.T) {
	tests := []struct {
		input string
		want  string
		found bool
	}{
		{"sql", "sql", true},
		{"SQLI", "sql", true},
		{"database", "sql", true},
		{"xss", "xss", true},
		{"api", "api", true},
		{"rest", "api", true},
		{"graphql", "graphql", true},
		{"gql", "graphql", true},
		{"passive", "passive", true},
		{"rce", "rce", true},
		{"ssrf", "ssrf", true},
		{"auth", "auth", true},
		{"fuzz", "fuzz", true},
		{"full", "full", true},
		{"unknown_mode_xyz", "", false},
	}

	for _, tt := range tests {
		m, ok := FindMode(tt.input)
		if ok != tt.found {
			t.Errorf("FindMode(%q) found = %v, want %v", tt.input, ok, tt.found)
		}
		if ok && m.Name != tt.want {
			t.Errorf("FindMode(%q).Name = %q, want %q", tt.input, m.Name, tt.want)
		}
	}
}

func TestResolveScanModes(t *testing.T) {
	// Single mode SQL
	allowed, isPassive, names, err := ResolveScanModes("sql")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if isPassive {
		t.Error("expected sql mode to not be passive")
	}
	if len(names) != 1 || names[0] != "sql" {
		t.Errorf("got names %v, want [sql]", names)
	}
	expectedSQL := []string{"nosql", "sqli"}
	sort.Strings(allowed)
	if !reflect.DeepEqual(allowed, expectedSQL) {
		t.Errorf("got modules %v, want %v", allowed, expectedSQL)
	}

	// Combination: api,graphql
	allowed, isPassive, names, err = ResolveScanModes("api,graphql")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if isPassive {
		t.Error("expected api,graphql to not be passive")
	}
	if len(names) != 2 {
		t.Errorf("expected 2 names, got %v", names)
	}
	hasGraphql := false
	hasAPI := false
	for _, mod := range allowed {
		if mod == "graphql" {
			hasGraphql = true
		}
		if mod == "api_exposure" {
			hasAPI = true
		}
	}
	if !hasGraphql || !hasAPI {
		t.Errorf("expected graphql and api_exposure in allowed modules, got %v", allowed)
	}

	// Passive mode
	allowed, isPassive, names, err = ResolveScanModes("passive")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !isPassive {
		t.Error("expected passive mode to be passive")
	}
	if len(allowed) == 0 {
		t.Error("expected passive mode to have allowed modules")
	}

	// Full mode returns nil (meaning all modules permitted)
	allowed, _, _, err = ResolveScanModes("full")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed != nil {
		t.Errorf("expected full mode to have nil allowed modules (all), got %v", allowed)
	}

	// Invalid mode error
	_, _, _, err = ResolveScanModes("invalid_mode")
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestApplyScanModes(t *testing.T) {
	cfg := DefaultScanConfig()
	if err := ApplyScanModes(&cfg, "sql"); err != nil {
		t.Fatalf("ApplyScanModes error: %v", err)
	}
	if !cfg.AllowsModule("sqli") {
		t.Error("expected sqli module to be allowed")
	}
	if cfg.AllowsModule("xss") {
		t.Error("expected xss module to NOT be allowed in sql mode")
	}
	if cfg.AllowsModule("command_injection") {
		t.Error("expected command_injection to NOT be allowed in sql mode")
	}
}

func TestPassiveModeRemainsPassiveAfterProfileNormalization(t *testing.T) {
	cfg := DefaultScanConfig()
	if err := ApplyScanModes(&cfg, "passive"); err != nil {
		t.Fatal(err)
	}
	// Simulate CLI defaults being assigned after --mode parsing.
	cfg.EnableOAST = true
	cfg.EnableFuzzing = true
	cfg.EnableWAFDetection = true
	cfg.EnableHeadlessCrawler = true
	cfg.Enable403BypassChecks = true
	cfg.EnableBusinessLogicChecks = true
	cfg.EnableRaceConditionTesting = true
	cfg.EnableSecondOrderTracking = true
	cfg = ApplyScanProfile(cfg)
	if !cfg.PassiveMode {
		t.Fatal("passive execution invariant was lost")
	}
	if cfg.EnableOAST || cfg.EnableFuzzing || cfg.EnableWAFDetection || cfg.EnableHeadlessCrawler ||
		cfg.Enable403BypassChecks || cfg.EnableBusinessLogicChecks || cfg.EnableRaceConditionTesting ||
		cfg.EnableSecondOrderTracking {
		t.Fatalf("passive mode re-enabled active behavior: %+v", cfg)
	}
	for _, active := range []string{"cicd_exposure", "git_recovery", "source_code_disclosure", "script_source", "cloud_storage", "cloud_posture"} {
		if cfg.AllowsModule(active) {
			t.Fatalf("passive mode must not run active module %q", active)
		}
	}
}
