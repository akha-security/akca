package report

import (
	"os/exec"
	"testing"
)

// Exercise the exported HTML's JavaScript with the actual header/pre sibling
// layout, unavailable APIs and rejected permissions. No clipboard data is
// changed on the host machine.
func TestReportClipboardPaths(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js is needed to execute report JavaScript")
	}
	if output, err := exec.Command(node, "testdata/clipboard_test.cjs").CombinedOutput(); err != nil {
		t.Fatalf("clipboard regression: %v\n%s", err, output)
	}
}
