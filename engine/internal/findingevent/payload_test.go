package findingevent

import (
	"testing"
	"time"
)

func TestPayloadCarriesReportFieldsToLiveEvent(t *testing.T) {
	payload := Payload(Data{
		FindingID: 12, ScanID: "scan-passive", Title: "Exposed secret",
		Severity: "High", VulnClass: "secret_exposure",
		Endpoint: "https://example.test/app.js", Location: "response_body",
		Method: "get", Payload: "secret-value", Signal: "passive_secret",
		Score: 0.82, ResponseStatus: 200, ResponseDuration: 125 * time.Millisecond,
		Passive: true,
	})

	checks := map[string]interface{}{
		"finding_id": int64(12), "severity": "high", "endpoint_url": "https://example.test/app.js",
		"vuln_class": "secret_exposure", "method": "GET", "payload_str": "secret-value",
		"confidence": "HighConfidence", "response_status": 200,
		"response_duration_ms": int64(125), "passive": true,
	}
	for key, want := range checks {
		if got := payload[key]; got != want {
			t.Fatalf("%s=%v, want %v", key, got, want)
		}
	}
}

func TestConfidenceLabelMatchesPersistenceThresholds(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{0.95, "Confirmed"}, {0.80, "HighConfidence"},
		{0.60, "Potential"}, {0.40, "NeedsManualReview"},
	}
	for _, tt := range tests {
		if got := ConfidenceLabel(tt.score); got != tt.want {
			t.Fatalf("ConfidenceLabel(%v)=%q, want %q", tt.score, got, tt.want)
		}
	}
}
