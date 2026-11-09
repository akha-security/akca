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
