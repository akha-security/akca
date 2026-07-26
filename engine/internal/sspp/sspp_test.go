package sspp

import "testing"

func TestAnalyzeProtoPollution(t *testing.T) {
	ok, sig := Analyze(`{"ok":true}`, 200, `{"polluted":true}`, 200, Probes()[0])
	if !ok || sig != "proto_pollution" {
		t.Fatalf("got ok=%v sig=%q", ok, sig)
	}
}

func TestAnalyzeErrorDisclosure(t *testing.T) {
	ok, sig := Analyze(`ok`, 200, `Cannot read property of __proto__`, 500, Probes()[0])
	if !ok || sig != "prototype_error_disclosure" {
		t.Fatalf("got ok=%v sig=%q", ok, sig)
	}
}

func TestProbesCount(t *testing.T) {
	if len(Probes()) < 7 {
		t.Fatalf("expected expanded probe set, got %d", len(Probes()))
	}
}
