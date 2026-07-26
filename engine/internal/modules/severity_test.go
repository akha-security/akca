package modules

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/verification"
)

func TestSSRFAndLFISeverityPreservesImpact(t *testing.T) {
	tests := []struct {
		module string
		conf   verification.ConfidenceLevel
		want   string
	}{
		{"ssrf", verification.Potential, "high"},
		{"lfi", verification.Potential, "high"},
		{"ssrf", verification.HighConfidence, "critical"},
		{"lfi", verification.Confirmed, "critical"},
		// Other Potential injection findings retain the conservative cap.
		{"sqli", verification.Potential, "medium"},
		// Unproven SSRF/LFI candidates are still kept low for manual review.
		{"ssrf", verification.NeedsManualReview, "low"},
		{"lfi", verification.NeedsManualReview, "low"},
	}

	for _, tt := range tests {
		if got := severityFor(tt.module, tt.conf); got != tt.want {
			t.Fatalf("severityFor(%q, %q)=%q, want %q", tt.module, tt.conf, got, tt.want)
		}
	}
}

func TestOpenRedirectSeverityIsMedium(t *testing.T) {
	tests := []struct {
		conf verification.ConfidenceLevel
		want string
	}{
		{verification.Confirmed, "medium"},
		{verification.HighConfidence, "medium"},
		{verification.Potential, "medium"},
		{verification.NeedsManualReview, "low"},
	}

	for _, tt := range tests {
		if got := severityFor("open_redirect", tt.conf); got != tt.want {
			t.Fatalf("severityFor(%q, %q)=%q, want %q", "open_redirect", tt.conf, got, tt.want)
		}
	}
}
