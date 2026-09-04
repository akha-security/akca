package deserialization

import (
	"testing"
)

func TestProbesList(t *testing.T) {
	probes := Probes()
	if len(probes) == 0 {
		t.Fatalf("expected non-empty deserialization probes")
	}
	foundPHP := false
	foundJava := false
	for _, p := range probes {
		if p.Language == "php" {
			foundPHP = true
		}
		if p.Language == "java" {
			foundJava = true
		}
	}
	if !foundPHP || !foundJava {
		t.Errorf("expected both PHP and Java probes, got php=%v, java=%v", foundPHP, foundJava)
	}
}

func TestAnalyzeResponse(t *testing.T) {
	probe := DeserProbe{
		Language: "php",
		Name:     "php_stdclass",
		Payload:  `O:8:"stdClass":1:{s:4:"akca";s:4:"test";}`,
		Signal:   "php_deser_marker",
		Severity: "high",
	}

	ok, sig := AnalyzeResponse("Normal 200 Page", 200, "Fatal error: Unserialize(): Error at offset 0 of 10 bytes", 500, probe)
	if !ok || sig != "deserialization_error_disclosure" {
		t.Errorf("expected deserialization error disclosure, got ok=%v, sig=%s", ok, sig)
	}

	okClean, _ := AnalyzeResponse("Normal 200 Page", 200, "Normal 200 Page", 200, probe)
	if okClean {
		t.Errorf("expected false for matching baseline")
	}
}
