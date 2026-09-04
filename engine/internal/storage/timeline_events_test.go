package storage

import (
	"path/filepath"
	"testing"
)

func TestSaveTimelineEventRoundTrip(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "timeline.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Conn().Exec(`INSERT INTO scans(id,status,config_json) VALUES ('scan-tl','running','{}')`); err != nil {
		t.Fatal(err)
	}

	if err := db.SaveTimelineEvent("scan-tl", "plugin_skipped", "unstable baseline",
		`{"module":"sqli","reason":"unstable baseline","endpoint":"https://example.com/search"}`); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveTimelineEvent("scan-tl", "plugin_skipped", "weak SSRF candidate",
		`{"module":"ssrf","reason":"weak SSRF candidate","endpoint":"https://example.com/api"}`); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveTimelineEvent("scan-tl", "scan_error", "timeout",
		`{"phase":"crawling"}`); err != nil {
		t.Fatal(err)
	}

	// Verify round-trip via ListTimelineUI
	rows, err := db.ListTimelineUI("scan-tl", "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected 3 timeline events, got %d", len(rows))
	}
	if rows[0].EventType != "plugin_skipped" || rows[2].EventType != "scan_error" {
		t.Fatalf("unexpected event types: %v, %v", rows[0].EventType, rows[2].EventType)
	}
}

func TestListSkippedModulesGrouping(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "skips.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Conn().Exec(`INSERT INTO scans(id,status,config_json) VALUES ('scan-sk','running','{}')`); err != nil {
		t.Fatal(err)
	}

	// Insert multiple skips with same module/reason
	for i, ep := range []string{"https://a.com/1", "https://a.com/2", "https://a.com/3"} {
		_ = i
		_ = db.SaveTimelineEvent("scan-sk", "plugin_skipped", "unstable baseline",
			`{"module":"sqli","reason":"unstable baseline","endpoint":"`+ep+`"}`)
	}
	// Different module
	_ = db.SaveTimelineEvent("scan-sk", "plugin_skipped", "weak candidate",
		`{"module":"ssrf","reason":"weak candidate","endpoint":"https://b.com/api"}`)

	records, err := db.ListSkippedModules("scan-sk")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 groups, got %d: %+v", len(records), records)
	}
	if records[0].Module != "sqli" || records[0].Count != 3 {
		t.Fatalf("first group unexpected: %+v", records[0])
	}
	if records[1].Module != "ssrf" || records[1].Count != 1 {
		t.Fatalf("second group unexpected: %+v", records[1])
	}
	if len(records[0].Endpoints) != 3 {
		t.Fatalf("expected 3 endpoints in first group, got %d", len(records[0].Endpoints))
	}
}

func TestIsDiagnosticEvent(t *testing.T) {
	tests := []struct {
		eventType string
		want      bool
	}{
		{"plugin_skipped", true},
		{"scan_error", true},
		{"coverage_gap", true},
		{"waf_detected", true},
		{"oast_probe_failed", true},
		{"oast_probe_sent", true},
		{"resource_limit_reached", true},
		{"finding_detected", false},
		{"health_snapshot", false},
		{"log", false},
	}
	for _, tt := range tests {
		if got := IsDiagnosticEvent(tt.eventType); got != tt.want {
			t.Errorf("IsDiagnosticEvent(%q) = %v, want %v", tt.eventType, got, tt.want)
		}
	}
}
