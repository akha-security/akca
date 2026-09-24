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
	if strings.Contains(script, ".value =") || strings.Contains(script, ".submit(") {
		t.Fatal("discovery must not fill or submit forms")
	}
	if !strings.Contains(script, "aria-controls") || !strings.Contains(script, "closest('form')") {
		t.Fatal("interactive discovery must restrict actions to non-form navigation controls")
	}
}
