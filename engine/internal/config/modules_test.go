package config

import "testing"

func TestAllowsModuleConfigFlags(t *testing.T) {
	cfg := DefaultScanConfig()
	cfg.EnableBusinessLogicChecks = false
	if cfg.AllowsModule("business_logic") {
		t.Fatal("expected business_logic disabled")
	}
	cfg.EnableRaceConditionTesting = false
	if cfg.AllowsModule("race_condition") {
		t.Fatal("expected race_condition disabled")
	}
	cfg.AllowedVulnerabilityClasses = []string{"xss", "sqli"}
	if !cfg.AllowsModule("xss") || !cfg.AllowsModule("sqli") {
		t.Fatal("expected xss/sqli allowed")
	}
	if cfg.AllowsModule("ssrf") {
		t.Fatal("expected ssrf blocked by allow list")
	}
}
