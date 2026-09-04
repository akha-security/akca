package app

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/modules"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/session"
	"github.com/akha-security/akca/engine/internal/verification"
)

func TestVulnerabilityPhasesReuseScanRunner(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.ScanID = "scan-shared-runner"
	e := &Engine{
		session:  session.NewScanSession(cfg),
		client:   &httpclient.Client{},
		scope:    scope.NewEngine(cfg),
		verifier: verification.NewEngine(nil, nil),
	}
	phaseA := e.vulnModuleRunner()
	phaseB := e.vulnModuleRunner()
	if phaseA == nil || phaseA != phaseB {
		t.Fatal("module phases must reuse one scan-scoped Runner so second-order markers survive")
	}
}

func TestFullScanModuleOrderCoversCatalog(t *testing.T) {
	ordered := map[string]struct{}{}
	for _, item := range fullScanModuleOrder {
		ordered[item.name] = struct{}{}
	}
	var missing []string
	for _, name := range modules.ModuleCatalog() {
		if _, ok := ordered[name]; !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("catalog modules missing from full scan order: %v", missing)
	}
}

func TestFullScanModuleOrderStartsWithPassiveAndExposureModules(t *testing.T) {
	wantPrefix := []string{
		"security_headers",
		"cookie_security",
		"tls_misconfig",
		"sensitive_data",
		"secret_exposure",
		"vulnerable_components",
		"known_cve",
		"script_source",
	}
	if len(fullScanModuleOrder) < len(wantPrefix) {
		t.Fatalf("full scan module order too short: %d", len(fullScanModuleOrder))
	}
	seen := map[string]bool{}
	for i, item := range fullScanModuleOrder {
		if item.name == "" || item.title == "" {
			t.Fatalf("module order item %d has empty name/title: %+v", i, item)
		}
		if seen[item.name] {
			t.Fatalf("module %q appears more than once in full scan order", item.name)
		}
		seen[item.name] = true
	}
	for i, want := range wantPrefix {
		if got := fullScanModuleOrder[i].name; got != want {
			t.Fatalf("module order[%d] = %q, want %q", i, got, want)
		}
	}
	for _, name := range []string{"blind_xss", "sqli", "command_injection", "ssrf", "xxe", "lfi"} {
		for _, item := range fullScanModuleOrder {
			if item.name == name && !item.usesOAST {
				t.Fatalf("module %q should trigger module-level OAST drain", name)
			}
		}
	}
}

func TestScanModeModuleFiltering(t *testing.T) {
	// Mode: sql
	cfgSQL := config.DefaultScanConfig()
	if err := config.ApplyScanModes(&cfgSQL, "sql"); err != nil {
		t.Fatalf("ApplyScanModes(sql) err: %v", err)
	}
	for _, item := range fullScanModuleOrder {
		allowed := cfgSQL.AllowsModule(item.name)
		if item.name == "sqli" || item.name == "nosql" {
			if !allowed {
				t.Errorf("expected module %q to be allowed in sql mode", item.name)
			}
		} else {
			if allowed {
				t.Errorf("expected module %q to be BLOCKED in sql mode", item.name)
			}
		}
	}

	// Mode: xss
	cfgXSS := config.DefaultScanConfig()
	if err := config.ApplyScanModes(&cfgXSS, "xss"); err != nil {
		t.Fatalf("ApplyScanModes(xss) err: %v", err)
	}
	if !cfgXSS.AllowsModule("xss") || !cfgXSS.AllowsModule("blind_xss") {
		t.Error("expected xss and blind_xss to be allowed in xss mode")
	}
	if cfgXSS.AllowsModule("sqli") || cfgXSS.AllowsModule("security_headers") {
		t.Error("expected sqli and security_headers to be BLOCKED in xss mode")
	}
}
