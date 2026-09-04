package storage

import (
	"time"
)

func (db *DB) EnsureScan(scanID string) error {
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	_, err := db.conn.Exec(
		`INSERT INTO scans (id, status, config_json, started_at, created_at, updated_at) VALUES (?, 'running', '{}', ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET updated_at = ?`,
		scanID, now, now, now, now,
	)
	return err
}

// UpdateScanStatus updates the status of a scan (e.g. running, completed, failed, stopped).
func (db *DB) UpdateScanStatus(scanID, status string) error {
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	if status == "completed" || status == "failed" || status == "stopped" || status == "partial" || status == "timeout" {
		_, err := db.conn.Exec(
			`UPDATE scans SET status = ?, completed_at = COALESCE(completed_at, ?), updated_at = ? WHERE id = ?`,
			status, now, now, scanID,
		)
		return err
	}
	_, err := db.conn.Exec(
		`UPDATE scans SET status = ?, updated_at = ? WHERE id = ?`,
		status, now, scanID,
	)
	return err
}

// UpdateScanFinished records the final status, total requests, and completion timestamp.
func (db *DB) UpdateScanFinished(scanID, status string, totalRequests int64, startedAt, completedAt time.Time) error {
	startStr := startedAt.UTC().Format("2006-01-02 15:04:05")
	compStr := completedAt.UTC().Format("2006-01-02 15:04:05")
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	_, err := db.conn.Exec(
		`UPDATE scans SET status = ?, requests_sent = MAX(COALESCE(requests_sent, 0), ?), started_at = ?, completed_at = ?, updated_at = ? WHERE id = ?`,
		status, totalRequests, startStr, compStr, now, scanID,
	)
	return err
}

// UpdateScanMetrics persists real-time request counts for a scan.
func (db *DB) UpdateScanMetrics(scanID string, totalRequests int64) error {
	_, err := db.conn.Exec(
		`UPDATE scans SET requests_sent = MAX(COALESCE(requests_sent, 0), ?), updated_at = datetime('now') WHERE id = ?`,
		totalRequests, scanID,
	)
	return err
}

// UpdateScanConfig persists the sanitized configuration JSON for a scan.
func (db *DB) UpdateScanConfig(scanID, configJSON string) error {
	_, err := db.conn.Exec(
		`UPDATE scans SET config_json = ?, updated_at = datetime('now') WHERE id = ?`,
		configJSON, scanID,
	)
	return err
}
