package crawler

import (
	"strings"
	"testing"
)

func TestGenerateSmartActionScript(t *testing.T) {
	cfg := DefaultSmartActionConfig()
	script := GenerateSmartActionScript(cfg)

	if !strings.Contains(script, "shadowRoot") {
		t.Fatal("script should support Shadow DOM traversal")
	}
	if !strings.Contains(script, "crawler@akca-test.local") {
		t.Fatal("script should fill email inputs")
	}
	if !strings.Contains(script, "dispatchEvent") {
		t.Fatal("script should dispatch synthetic events")
	}
}
