package testlab

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/modules"
	"github.com/akha-security/akca/engine/internal/payloadgen"
)

func TestMergeEssentialLabPayloadsAddsMissingSQLi(t *testing.T) {
	target := modules.ScanTarget{EndpointURL: "http://127.0.0.1/api/users", Parameter: "id"}
	base := payloadgen.GenerationResult{Payloads: []payloadgen.Payload{
		{VulnClass: "xss", Value: `<script>alert(1)</script>`},
	}}
	merged := mergeEssentialLabPayloads(base, labFallbackPayloads(target))
	var hasSQLi bool
	for _, p := range merged.Payloads {
		if p.VulnClass == "sqli" {
			hasSQLi = true
			break
		}
	}
	if !hasSQLi {
		t.Fatalf("expected merged sqli payloads, got %+v", merged.Payloads)
	}
}

func payloadClasses(payloads []payloadgen.Payload) map[string]int {
	out := map[string]int{}
	for _, p := range payloads {
		out[p.VulnClass]++
	}
	return out
}
