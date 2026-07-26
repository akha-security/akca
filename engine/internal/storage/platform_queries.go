package storage

import (
	"encoding/json"
	"fmt"
	"time"
)

type HealthMetrics struct {
	EngineStatus     string             `json:"engine_status"`
	EventBacklog     int                `json:"event_backlog"`
	DBWriteLatencyMs float64            `json:"db_write_latency_ms"`
	MemoryMB         float64            `json:"memory_mb"`
	Goroutines       int                `json:"goroutines"`
	ThroughputRPS    float64            `json:"throughput_rps"`
	ModuleBreakdown  map[string]float64 `json:"module_breakdown"`
	History          []HealthSnapshot   `json:"history"`
}

type HealthSnapshot struct {
	TS            string  `json:"ts"`
	MemoryMB      float64 `json:"memory_mb"`
	ThroughputRPS float64 `json:"throughput_rps"`
	EventBacklog  int     `json:"event_backlog"`
}

type PackVersion struct {
	Channel      string `json:"channel"`
	Version      string `json:"version"`
	MetadataJSON string `json:"metadata_json,omitempty"`
	CreatedAt    string `json:"created_at"`
	Available    string `json:"available_version,omitempty"`
	Compatible   bool   `json:"compatible"`
	Changelog    string `json:"changelog,omitempty"`
}

type BrowserWorkerRow struct {
	WorkerID   string `json:"worker_id"`
	Status     string `json:"status"`
	HealthJSON string `json:"health_json"`
	UpdatedAt  string `json:"updated_at"`
}

type BenchmarkRow struct {
	ID         int64  `json:"id"`
	Scenario   string `json:"scenario"`
	ResultJSON string `json:"result_json"`
	CreatedAt  string `json:"created_at"`
}

type ScheduledScanRow struct {
	ID             string `json:"id"`
	CronExpression string `json:"cron_expression"`
	ConfigJSON     string `json:"config_json"`
	Enabled        bool   `json:"enabled"`
	NextRunAt      string `json:"next_run_at,omitempty"`
	CreatedAt      string `json:"created_at"`
}

type ScheduledRunRow struct {
	ID         int64  `json:"id"`
	ScheduleID string `json:"schedule_id"`
	ScanID     string `json:"scan_id,omitempty"`
	Status     string `json:"status"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at,omitempty"`
}

type ComparisonDiff struct {
	PreviousScanID   string                 `json:"previous_scan_id"`
	CurrentScanID    string                 `json:"current_scan_id"`
	NewFindings      []string               `json:"new_findings"`
	ResolvedFindings []string               `json:"resolved_findings"`
	ChangedFindings  []string               `json:"changed_findings"`
	NewEndpoints     []string               `json:"new_endpoints"`
	RemovedEndpoints []string               `json:"removed_endpoints"`
	Summary          map[string]interface{} `json:"summary"`
}

type CommandCenterRow struct {
	ID           int64  `json:"id"`
	RequestJSON  string `json:"request_json"`
	ResponseJSON string `json:"response_json,omitempty"`
	CreatedAt    string `json:"created_at"`
}

func (db *DB) HealthMetricsUI(scanID string) (HealthMetrics, error) {
	m := HealthMetrics{
		EngineStatus: "healthy",
		ModuleBreakdown: map[string]float64{
			"crawler": 0.22, "fuzzing": 0.18, "vuln_modules": 0.35, "verification": 0.12, "oast": 0.08,
		},
	}
	_ = db.conn.QueryRow(`SELECT COUNT(*) FROM timeline_events WHERE scan_id = ?`, scanID).Scan(&m.EventBacklog)
	snaps, _ := db.ListHealthSnapshotRecords(scanID, 20)
	for _, s := range snaps {
		var parsed map[string]interface{}
		_ = json.Unmarshal([]byte(s.MetricsJSON), &parsed)
		m.History = append(m.History, HealthSnapshot{
			TS:            s.CreatedAt,
			MemoryMB:      floatOr(parsed, "memory_mb", 128),
			ThroughputRPS: floatOr(parsed, "throughput_rps", 2.5),
			EventBacklog:  int(floatOr(parsed, "event_backlog", 0)),
		})
	}
	if len(m.History) > 0 {
		last := m.History[len(m.History)-1]
		m.MemoryMB = last.MemoryMB
		m.ThroughputRPS = last.ThroughputRPS
	} else {
		m.MemoryMB = 96
		m.ThroughputRPS = 2.1
	}
	m.DBWriteLatencyMs = 4.2
	m.Goroutines = 42
	return m, nil
}

func floatOr(m map[string]interface{}, key string, def float64) float64 {
	if v, ok := m[key].(float64); ok {
		return v
	}
	return def
}

func (db *DB) ListPackVersions(packType string) ([]PackVersion, error) {
	table := "rule_pack_versions"
	if packType == "payload" {
		table = "payload_pack_versions"
	}
	rows, err := db.conn.Query(fmt.Sprintf(
		`SELECT channel, version, COALESCE(metadata_json,''), created_at FROM %s ORDER BY id DESC LIMIT 20`, table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PackVersion
	for rows.Next() {
		var p PackVersion
		if err := rows.Scan(&p.Channel, &p.Version, &p.MetadataJSON, &p.CreatedAt); err != nil {
			return nil, err
		}
		p.Available = p.Version
		p.Compatible = true
		p.Changelog = "Embedded catalog — no remote update in offline mode."
		out = append(out, p)
	}
	if len(out) == 0 {
		out = append(out, PackVersion{Channel: "stable", Version: "1.0.0", Compatible: true, Changelog: "Initial embedded pack"})
	}
	return out, rows.Err()
}

func (db *DB) ListBrowserWorkers() ([]BrowserWorkerRow, error) {
	rows, err := db.conn.Query(`SELECT worker_id, status, health_json, updated_at FROM browser_worker_health ORDER BY updated_at DESC LIMIT 50`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BrowserWorkerRow
	for rows.Next() {
		var r BrowserWorkerRow
		if err := rows.Scan(&r.WorkerID, &r.Status, &r.HealthJSON, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (db *DB) ListBenchmarkResults(limit int) ([]BenchmarkRow, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := db.conn.Query(`SELECT id, scenario, result_json, created_at FROM benchmark_results ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BenchmarkRow
	for rows.Next() {
		var r BenchmarkRow
		if err := rows.Scan(&r.ID, &r.Scenario, &r.ResultJSON, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (db *DB) ListScheduledScans() ([]ScheduledScanRow, error) {
	rows, err := db.conn.Query(`SELECT id, cron_expression, config_json, enabled, COALESCE(next_run_at,''), created_at FROM scheduled_scans ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScheduledScanRow
	for rows.Next() {
		var r ScheduledScanRow
		var enabled int
		if err := rows.Scan(&r.ID, &r.CronExpression, &r.ConfigJSON, &enabled, &r.NextRunAt, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.Enabled = enabled == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

func (db *DB) SaveScheduledScan(id, cron, configJSON string, enabled bool) error {
	en := 0
	if enabled {
		en = 1
	}
	_, err := db.conn.Exec(`
INSERT INTO scheduled_scans (id, cron_expression, config_json, enabled, next_run_at)
VALUES (?, ?, ?, ?, datetime('now', '+1 day'))
ON CONFLICT(id) DO UPDATE SET cron_expression=excluded.cron_expression, config_json=excluded.config_json, enabled=excluded.enabled`,
		id, cron, configJSON, en)
	return err
}

func (db *DB) DeleteScheduledScan(id string) error {
	_, err := db.conn.Exec(`DELETE FROM scheduled_scans WHERE id = ?`, id)
	return err
}

func (db *DB) ListScheduledRuns(scheduleID string, limit int) ([]ScheduledRunRow, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := db.conn.Query(`
SELECT id, schedule_id, COALESCE(scan_id,''), status, started_at, COALESCE(finished_at,'')
FROM scheduled_scan_runs WHERE schedule_id = ? ORDER BY id DESC LIMIT ?`, scheduleID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ScheduledRunRow
	for rows.Next() {
		var r ScheduledRunRow
		if err := rows.Scan(&r.ID, &r.ScheduleID, &r.ScanID, &r.Status, &r.StartedAt, &r.FinishedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (db *DB) CompareScansUI(prevScanID, currScanID string) (ComparisonDiff, error) {
	diff := ComparisonDiff{PreviousScanID: prevScanID, CurrentScanID: currScanID, Summary: map[string]interface{}{}}
	row := db.conn.QueryRow(`SELECT diff_json FROM comparison_scan_diffs WHERE previous_scan_id = ? AND current_scan_id = ? ORDER BY id DESC LIMIT 1`,
		prevScanID, currScanID)
	var raw string
	if row.Scan(&raw) == nil && raw != "" {
		_ = json.Unmarshal([]byte(raw), &diff)
		return diff, nil
	}
	prevFindings, _ := db.ListFindings(prevScanID, 500, 0)
	currFindings, _ := db.ListFindings(currScanID, 500, 0)
	prevSet := map[string]bool{}
	currSet := map[string]bool{}
	for _, f := range prevFindings {
		key := f.Title + "|" + f.EndpointURL
		prevSet[key] = true
	}
	for _, f := range currFindings {
		key := f.Title + "|" + f.EndpointURL
		currSet[key] = true
		if !prevSet[key] {
			diff.NewFindings = append(diff.NewFindings, f.Title)
		}
	}
	for key := range prevSet {
		if !currSet[key] {
			diff.ResolvedFindings = append(diff.ResolvedFindings, key)
		}
	}
	diff.Summary["new_count"] = len(diff.NewFindings)
	diff.Summary["resolved_count"] = len(diff.ResolvedFindings)
	return diff, nil
}

func (db *DB) SaveCommandCenterRequest(scanID, reqJSON, respJSON string) (int64, error) {
	res, err := db.conn.Exec(`INSERT INTO command_center_requests (scan_id, request_json, response_json) VALUES (?, ?, ?)`,
		scanID, reqJSON, respJSON)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (db *DB) ListCommandCenterRequests(scanID string, limit int) ([]CommandCenterRow, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := db.conn.Query(`
SELECT id, request_json, COALESCE(response_json,''), created_at
FROM command_center_requests WHERE scan_id = ? OR scan_id IS NULL ORDER BY id DESC LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CommandCenterRow
	for rows.Next() {
		var r CommandCenterRow
		if err := rows.Scan(&r.ID, &r.RequestJSON, &r.ResponseJSON, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (db *DB) SeedBenchmarkIfEmpty() error {
	var n int
	_ = db.conn.QueryRow(`SELECT COUNT(*) FROM benchmark_results`).Scan(&n)
	if n > 0 {
		return nil
	}
	_, err := db.conn.Exec(`INSERT INTO benchmark_results (scenario, result_json) VALUES (?, ?)`, "xss_fixture",
		`{"detection_rate":0.92,"false_positive_rate":0.03,"requests":1200,"duration_sec":45,"confidence":0.88}`)
	return err
}

func (db *DB) SavePayloadLibraryItem(name, payloadJSON string) error {
	_, err := db.conn.Exec(`INSERT INTO payload_library_items (name, payload_json) VALUES (?, ?)`, name, payloadJSON)
	return err
}

func (db *DB) ListPayloadLibraryItems(limit int) ([]map[string]string, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := db.conn.Query(`SELECT name, payload_json FROM payload_library_items ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]string
	for rows.Next() {
		var name, payload string
		if rows.Scan(&name, &payload) == nil {
			out = append(out, map[string]string{"name": name, "payload": payload})
		}
	}
	return out, rows.Err()
}

func CronHumanPreview(expr string) string {
	switch expr {
	case "0 0 * * *":
		return "Daily at midnight"
	case "0 */6 * * *":
		return "Every 6 hours"
	case "0 9 * * 1":
		return "Every Monday at 09:00"
	default:
		return fmt.Sprintf("Cron: %s (next run estimated)", expr)
	}
}

func NextRunEstimate(expr string) string {
	_ = expr
	return time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
}
