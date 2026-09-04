package domtaint

import (
	"strings"
	"testing"
)

func TestGenerateHarness(t *testing.T) {
	canary := "akca_taint_12345"
	harness := GenerateHarness(canary)

	if !strings.Contains(harness, canary) {
		t.Fatal("harness should contain canary string")
	}
	if !strings.Contains(harness, "window.eval") {
		t.Fatal("harness should hook eval")
	}
	if !strings.Contains(harness, "innerHTML") {
		t.Fatal("harness should hook innerHTML")
	}
}

func TestParseTaintReports(t *testing.T) {
	canary := "akca_canary_xss"
	mockJSON := `[
		{
			"sink": "Element.innerHTML",
			"category": "dom_injection",
			"severity": "high",
			"sink_value": "<div>hello akca_canary_xss</div>",
			"stack_trace": "Error\n    at render (app.js:42:15)",
			"url": "https://example.com/#akca_canary_xss",
			"canary": "akca_canary_xss",
			"timestamp": 1700000000000
		}
	]`

	reports, err := ParseTaintReports(mockJSON, canary)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("expected 1 report, got %d", len(reports))
	}

	r := reports[0]
	if r.Sink != "Element.innerHTML" {
		t.Errorf("expected Element.innerHTML sink, got %s", r.Sink)
	}
	if r.Category != SinkDOMInjection {
		t.Errorf("expected SinkDOMInjection, got %s", r.Category)
	}
	if !r.Confirmed {
		t.Error("expected confirmed to be true")
	}
}

func TestStaticScanCode(t *testing.T) {
	vulnerableJS := `
		window.addEventListener('message', function(event) {
			eval(event.data);
		});
	`

	warnings := StaticScanCode(vulnerableJS)
	if len(warnings) == 0 {
		t.Fatal("expected static warnings for unvalidated postMessage")
	}

	hasPostMessageWarn := false
	for _, w := range warnings {
		if strings.Contains(w.Title, "PostMessage") {
			hasPostMessageWarn = true
		}
	}
	if !hasPostMessageWarn {
		t.Errorf("expected postMessage warning, got: %+v", warnings)
	}
}
