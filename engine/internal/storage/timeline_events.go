package storage

import (
	"encoding/json"
	"strings"
)

// SaveTimelineEvent persists a diagnostic event to the timeline_events table.
// Only high-diagnostic-value events (e.g. plugin_skipped, scan_error) should
// be saved — callers are expected to filter event types before calling.
func (db *DB) SaveTimelineEvent(scanID, eventType, summary, eventJSON string) error {
	_, err := db.conn.Exec(`
INSERT INTO timeline_events (scan_id, event_type, summary, event_json)
VALUES (?, ?, ?, ?)`, scanID, eventType, summary, eventJSON)
	return err
}

// SkippedModuleRecord groups plugin_skipped events by module and reason.
type SkippedModuleRecord struct {
	Module    string   `json:"module"`
	Reason    string   `json:"reason"`
	Count     int      `json:"count"`
	Endpoints []string `json:"endpoints"`
}

// ListSkippedModules returns plugin_skipped events for a scan, grouped by
// module and reason. This enables both CLI summary panels and future UI
// displays to show why modules were skipped on specific targets.
func (db *DB) ListSkippedModules(scanID string) ([]SkippedModuleRecord, error) {
	rows, err := db.conn.Query(`
SELECT event_json FROM timeline_events
WHERE scan_id = ? AND event_type = 'plugin_skipped'
ORDER BY id ASC`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type groupKey struct{ module, reason string }
	groups := map[groupKey]*SkippedModuleRecord{}
	var order []groupKey

	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var parsed map[string]interface{}
		if json.Unmarshal([]byte(raw), &parsed) != nil {
			continue
		}
		module, _ := parsed["module"].(string)
		reason, _ := parsed["reason"].(string)
		endpoint, _ := parsed["endpoint"].(string)
		if module == "" {
			continue
		}
		key := groupKey{module, reason}
		if _, exists := groups[key]; !exists {
			groups[key] = &SkippedModuleRecord{Module: module, Reason: reason}
			order = append(order, key)
		}
		rec := groups[key]
		rec.Count++
		if endpoint != "" && len(rec.Endpoints) < 5 {
			rec.Endpoints = append(rec.Endpoints, endpoint)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]SkippedModuleRecord, 0, len(order))
	for _, key := range order {
		out = append(out, *groups[key])
	}
	return out, nil
}

// isDiagnosticEvent returns true for event types that carry high diagnostic
// value and should be persisted to the timeline_events table.
func IsDiagnosticEvent(eventType string) bool {
	switch strings.ToLower(eventType) {
	case "plugin_skipped", "oast_probe_failed", "oast_probe_sent", "oast_verification_pending",
		"scan_error", "coverage_gap", "waf_detected", "resource_limit_reached":
		return true
	}
	return false
}
