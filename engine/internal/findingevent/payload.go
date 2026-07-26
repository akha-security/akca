// Package findingevent builds the canonical event payload used whenever a
// persisted finding is announced to interactive scan consumers.
package findingevent

import (
	"strings"
	"time"
)

// Data contains the report fields that are also useful in the live CLI.
// Keeping these fields together prevents passive scanners from persisting a
// richer finding than the one they publish during a scan.
type Data struct {
	FindingID        int64
	ScanID           string
	Title            string
	Severity         string
	VulnClass        string
	Endpoint         string
	Parameter        string
	Location         string
	Method           string
	Payload          string
	Signal           string
	Confidence       string
	Score            float64
	ResponseStatus   int
	ResponseDuration time.Duration
	Passive          bool
}

// Payload returns the standard finding_detected payload understood by the CLI
// and other event consumers.
func Payload(data Data) map[string]interface{} {
	score := data.Score
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}
	confidence := strings.TrimSpace(data.Confidence)
	if confidence == "" {
		confidence = ConfidenceLabel(score)
	}

	payload := map[string]interface{}{
		"finding_id":   data.FindingID,
		"scan_id":      data.ScanID,
		"title":        data.Title,
		"severity":     strings.ToLower(strings.TrimSpace(data.Severity)),
		"vuln_class":   data.VulnClass,
		"endpoint":     data.Endpoint,
		"endpoint_url": data.Endpoint,
		"parameter":    data.Parameter,
		"location":     data.Location,
		"method":       strings.ToUpper(strings.TrimSpace(data.Method)),
		"payload_str":  data.Payload,
		"signal":       data.Signal,
		"confidence":   confidence,
		"score":        score,
		"passive":      data.Passive,
	}
	if data.ResponseStatus > 0 {
		payload["response_status"] = data.ResponseStatus
	}
	if data.ResponseDuration > 0 {
		payload["response_duration_ms"] = data.ResponseDuration.Milliseconds()
	}
	return payload
}

// ConfidenceLabel mirrors the label stored in the findings table.
func ConfidenceLabel(score float64) string {
	switch {
	case score >= 0.9:
		return "Confirmed"
	case score >= 0.75:
		return "HighConfidence"
	case score >= 0.55:
		return "Potential"
	default:
		return "NeedsManualReview"
	}
}
