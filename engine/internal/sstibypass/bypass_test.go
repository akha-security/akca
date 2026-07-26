package sstibypass

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/payloadgen"
)

func TestEsotericPayloadsPython(t *testing.T) {
	out := EsotericPayloads(payloadgen.TechHints{Framework: "Flask"})
	if len(out) < 2 {
		t.Fatalf("expected python bypass payloads, got %d", len(out))
	}
}

func TestAnalyzeConfigLeak(t *testing.T) {
	p := payloadgen.Payload{ExpectedSignal: "ssti_jinja_config_rce"}
	sig := Analyze(p, `SECRET_KEY=abc123`, "hello")
	if sig != "config_leak" {
		t.Fatalf("expected config_leak, got %q", sig)
	}
}

func TestAnalyzeCommandOutput(t *testing.T) {
	p := payloadgen.Payload{ExpectedSignal: "ssti_jinja_mro_bypass"}
	sig := Analyze(p, "uid=1000(www-data)", "hello")
	if sig != "command_output" {
		t.Fatalf("expected command_output, got %q", sig)
	}
}

func TestEsotericPayloadsDefault(t *testing.T) {
	out := EsotericPayloads(payloadgen.TechHints{})
	if len(out) != 0 {
		t.Fatalf("unfingerprinted targets must not receive esoteric SSTI probes: %+v", out)
	}
}
