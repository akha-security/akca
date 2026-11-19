package config

import "testing"

func TestPHP2ShellActiveAcceptsExplicitLabHost(t *testing.T) {
	cfg := DefaultScanConfig()
	cfg.PHP2ShellActive = true
	if err := ApplyScanModes(&cfg, "php2shell"); err != nil {
		t.Fatal(err)
	}
	cfg.Targets = []string{"https://php2shell.lab.example/index.php"}
	if err := cfg.ValidatePHP2ShellOptions(); err != nil {
		t.Fatalf("explicit lab DNS target rejected: %v", err)
	}
	cfg.Targets = []string{"http://127.0.0.1:8080/index.php"}
	if err := cfg.ValidatePHP2ShellOptions(); err != nil {
		t.Fatalf("loopback lab target rejected: %v", err)
	}
}

func TestPHP2ShellActiveCanBeEnabledAfterDedicatedModeResolution(t *testing.T) {
	cfg := DefaultScanConfig()
	cfg.Targets = []string{"http://127.0.0.1:8080/index.php"}
	if err := ApplyScanModes(&cfg, "php2shell"); err != nil {
		t.Fatal(err)
	}

	// This is the CLI ordering: resolve --mode first, then enable the bounded
	// active assessment that is implicit in the dedicated mode.
	cfg.SetPHP2ShellActive(true)

	if cfg.PassiveMode {
		t.Fatal("dedicated active PHP2Shell mode remained passive")
	}
	if !cfg.OnlyPHP2Shell() || !cfg.AllowsModule("php2shell") || cfg.AllowsModule("sqli") {
		t.Fatalf("dedicated module selection widened: %v", cfg.AllowedVulnerabilityClasses)
	}
	if cfg.EnableFuzzing || cfg.EnableOAST || cfg.EnableWAFDetection || cfg.EnableHeadlessCrawler || cfg.FollowRedirects {
		t.Fatal("dedicated PHP2Shell mode re-enabled discovery or unrelated active phases")
	}
	if err := cfg.ValidatePHP2ShellOptions(); err != nil {
		t.Fatalf("CLI-ordered dedicated mode rejected: %v", err)
	}
}

func TestPHP2ShellActiveSupportsNormalFullScan(t *testing.T) {
	cfg := DefaultScanConfig()
	cfg.PHP2ShellActive = true
	cfg.Targets = []string{"http://127.0.0.1:8080"}
	if err := ApplyScanModes(&cfg, ""); err != nil {
		t.Fatal(err)
	}
	if err := cfg.ValidatePHP2ShellOptions(); err != nil {
		t.Fatalf("active assessment should be accepted in a normal full scan: %v", err)
	}
	cfg.PassiveMode = true
	if err := cfg.ValidatePHP2ShellOptions(); err == nil {
		t.Fatal("active assessment must remain disabled in passive scans")
	}
}

func TestPHP2ShellActiveAllowsConfiguredCaptureProxy(t *testing.T) {
	cfg := DefaultScanConfig()
	cfg.PHP2ShellActive = true
	cfg.ProxyURL = "127.0.0.1:8080"
	if err := ApplyScanModes(&cfg, "php2shell"); err != nil {
		t.Fatal(err)
	}
	cfg.Targets = []string{"http://127.0.0.1:8080/index.php"}
	if err := cfg.ValidatePHP2ShellOptions(); err != nil {
		t.Fatalf("capture proxy should be accepted for an authorized lab target: %v", err)
	}
}

func TestPHP2ShellEndpointURLAddsIndexPHPForRootTarget(t *testing.T) {
	got, err := PHP2ShellEndpointURL("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://example.com/index.php" {
		t.Fatalf("endpoint = %q, want /index.php endpoint", got)
	}
	got, err = PHP2ShellEndpointURL("https://example.com/custom.php")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://example.com/custom.php" {
		t.Fatalf("explicit endpoint changed to %q", got)
	}
}
