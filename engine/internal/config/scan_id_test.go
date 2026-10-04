package config

import (
	"regexp"
	"testing"
)

func TestGenerateScanIDIsUniqueAndStorageSafe(t *testing.T) {
	targets := []string{"https://example.com", "https://api.example.com"}
	valid := regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := GenerateScanID(targets)
		if !valid.MatchString(id) {
			t.Fatalf("generated scan ID is not storage safe: %q", id)
		}
		if seen[id] {
			t.Fatalf("collision detected for repeated scan runs on the same target set: %s", id)
		}
		seen[id] = true
	}
}
