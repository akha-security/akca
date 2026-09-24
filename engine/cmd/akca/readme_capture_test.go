package main

import (
	"context"
	"os"
	"testing"

	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/testlab"
)

// Opt-in documentation capture: run the local lab and render its actual finding
// events with the production console writer. No findings are fabricated.
func TestReadmeCapture(t *testing.T) {
	path := os.Getenv("AKCA_README_CAPTURE")
	if path == "" {
		t.Skip("opt-in documentation capture")
	}
	lab := testlab.NewServer(testlab.ModeFull)
	defer lab.Close()
	db, err := storage.Open(t.TempDir() + "/capture.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	result, err := testlab.RunScan(context.Background(), db, testlab.Options{
		ScanID: "readme-local-lab", Lab: lab, Short: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	output, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	cw := NewConsoleWriter()
	enableColors()
	cw.out = output
	cw.interactive = true
	seen := map[string]bool{}
	for _, event := range result.Events.Events() {
		if event.Type != "finding_detected" {
			continue
		}
		class, _ := event.Payload["vuln_class"].(string)
		if (class != "sqli" && class != "xss" && class != "ssti") || seen[class] {
			continue
		}
		seen[class] = true
		if err := cw.WriteEvent(event); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) == 0 {
		t.Fatal("no injection findings captured")
	}
	t.Logf("captured actual lab findings: %v (%d requests)", seen, result.RequestCount)
}
