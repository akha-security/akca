package config

import (
	"encoding/json"
	"testing"
)

func TestWAFPayloadDefaultsAndStoredOptOut(t *testing.T) {
	cfg := ApplyScanProfile(DefaultScanConfig())
	if cfg.EffectiveWAFPayloadMode() != WAFPayloadAuto || cfg.EnableWAFBypassHeaders {
		t.Fatalf("auto must not enable bypass headers: mode=%s headers=%v", cfg.EffectiveWAFPayloadMode(), cfg.EnableWAFBypassHeaders)
	}
	// JSON choices must survive profiles and checkpoint round-trips even though
	// ExplicitScanOptions is deliberately not serialized.
	if err := json.Unmarshal([]byte(`{"waf_payload_mode":"off"}`), &cfg); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var restored ScanConfig
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	restored = ApplyScanProfile(restored)
	if restored.WAFPayloadsEnabled() {
		t.Fatal("stored opt-out was overwritten")
	}
	var legacy ScanConfig
	if err := json.Unmarshal([]byte(`{"enable_waf_bypass_headers":false}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.EffectiveWAFPayloadMode() != WAFPayloadAuto {
		t.Fatal("omitted mode must default to auto")
	}
	if err := json.Unmarshal([]byte(`{"enable_waf_bypass_headers":true,"waf_payload_mode":"off"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	legacy = ApplyScanProfile(legacy)
	if !legacy.EnableWAFBypassHeaders || legacy.WAFPayloadsEnabled() {
		t.Fatal("JSON header opt-in must survive independently of disabled payload adaptation")
	}
	cfg.WAFPayloadMode = "invalid"
	if err := cfg.Validate(); err == nil {
		t.Fatal("invalid WAF payload mode accepted")
	}
}

func TestPassiveOverridesForcedWAFPayloadsAndHeaders(t *testing.T) {
	cfg := DefaultScanConfig()
	cfg.WAFPayloadMode = WAFPayloadOn
	cfg.EnableWAFBypassHeaders = true
	cfg.Explicit.EnableWAFBypassHeaders = true
	cfg.PassiveMode = true
	if cfg.WAFPayloadsEnabled() {
		t.Fatal("un-normalized passive configuration enables adaptation")
	}
	cfg = ApplyScanProfile(cfg)
	if cfg.WAFPayloadMode != WAFPayloadOff || cfg.EnableWAFBypassHeaders {
		t.Fatal("profile re-enabled passive WAF mutations")
	}
}
