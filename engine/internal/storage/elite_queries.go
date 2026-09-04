package storage

import (
	"encoding/json"
	"time"
)

func (db *DB) SaveEncryptedSecretRef(scanID, secretKey string, ref interface{}) error {
	raw, _ := json.Marshal(ref)
	_, err := db.conn.Exec(`INSERT INTO encrypted_secret_refs (scan_id, secret_key, storage_mode, ref_json) VALUES (?, ?, ?, ?)`,
		scanID, secretKey, "encrypted", string(raw))
	return err
}

func (db *DB) LoadEncryptedSecretRef(scanID, secretKey string) (string, error) {
	var raw string
	err := db.conn.QueryRow(`
SELECT ref_json FROM encrypted_secret_refs
WHERE scan_id = ? AND secret_key = ?
ORDER BY id DESC LIMIT 1`, scanID, secretKey).Scan(&raw)
	return raw, err
}

func (db *DB) Ping() error {
	return db.conn.Ping()
}

func (db *DB) SaveAuthProfile(scanID, id, name, profileJSON string) error {
	_, err := db.conn.Exec(`
INSERT INTO auth_profiles (id, scan_id, name, profile_json) VALUES (?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET name=excluded.name, profile_json=excluded.profile_json`,
		id, scanID, name, profileJSON)
	return err
}

func (db *DB) SaveRoleProfile(scanID, id, name, authProfileID, profileJSON string) error {
	_, err := db.conn.Exec(`
INSERT INTO role_profiles (id, scan_id, name, auth_profile_id, profile_json) VALUES (?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET name=excluded.name, auth_profile_id=excluded.auth_profile_id, profile_json=excluded.profile_json`,
		id, scanID, name, authProfileID, profileJSON)
	return err
}

func (db *DB) SaveCheckpoint(scanID, checkpointJSON string) error {
	_, err := db.conn.Exec(`INSERT INTO scan_checkpoints (scan_id, checkpoint_json) VALUES (?, ?)`, scanID, checkpointJSON)
	if err != nil {
		return err
	}
	_, _ = db.conn.Exec(`
DELETE FROM scan_checkpoints
WHERE scan_id = ? AND id NOT IN (
  SELECT id FROM scan_checkpoints WHERE scan_id = ? ORDER BY id DESC LIMIT 5
)`, scanID, scanID)
	return nil
}

func (db *DB) SaveResumeState(scanID, stateJSON string) error {
	_, err := db.conn.Exec(`INSERT INTO resume_state (scan_id, state_json) VALUES (?, ?)`, scanID, stateJSON)
	return err
}

func (db *DB) SaveHealthSnapshot(scanID, metricsJSON string) error {
	_, err := db.conn.Exec(`INSERT INTO health_snapshots (scan_id, metrics_json) VALUES (?, ?)`, scanID, metricsJSON)
	return err
}

func (db *DB) SaveBenchmarkResult(scenario, resultJSON string) error {
	_, err := db.conn.Exec(`INSERT INTO benchmark_results (scenario, result_json) VALUES (?, ?)`, scenario, resultJSON)
	return err
}

func (db *DB) InsertRulePackVersion(channel, version, metadata string) error {
	_, err := db.conn.Exec(`INSERT INTO rule_pack_versions (channel, version, metadata_json) VALUES (?, ?, ?)`, channel, version, metadata)
	return err
}

func (db *DB) InsertPayloadPackVersion(channel, version, metadata string) error {
	_, err := db.conn.Exec(`INSERT INTO payload_pack_versions (channel, version, metadata_json) VALUES (?, ?, ?)`, channel, version, metadata)
	return err
}

func (db *DB) UpsertBrowserWorker(workerID, status, healthJSON string) error {
	_, err := db.conn.Exec(`INSERT INTO browser_worker_health (worker_id, status, health_json) VALUES (?, ?, ?)`, workerID, status, healthJSON)
	return err
}

func (db *DB) SaveProxySession(sessionID, sessionJSON string) error {
	_, err := db.conn.Exec(`
INSERT INTO proxy_intercept_sessions (id, session_json) VALUES (?, ?)
ON CONFLICT(id) DO UPDATE SET session_json=excluded.session_json`, sessionID, sessionJSON)
	return err
}

func (db *DB) SaveProxyTraffic(sessionID, trafficJSON string) error {
	_, err := db.conn.Exec(`INSERT INTO proxy_traffic_records (session_id, traffic_json) VALUES (?, ?)`, sessionID, trafficJSON)
	return err
}

func (db *DB) ListProxyTraffic(sessionID string, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := db.conn.Query(`SELECT traffic_json FROM proxy_traffic_records WHERE session_id = ? ORDER BY id DESC LIMIT ?`, sessionID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var raw string
		if rows.Scan(&raw) == nil {
			out = append(out, raw)
		}
	}
	return out, rows.Err()
}

func (db *DB) SaveComparisonDiff(prevScanID, currScanID, diffJSON string) error {
	_, err := db.conn.Exec(`INSERT INTO comparison_scan_diffs (previous_scan_id, current_scan_id, diff_json) VALUES (?, ?, ?)`,
		prevScanID, currScanID, diffJSON)
	return err
}

func (db *DB) ListEndpointURLs(scanID string) ([]string, error) {
	rows, err := db.conn.Query(`SELECT url FROM endpoints WHERE scan_id = ?`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if rows.Scan(&u) == nil {
			out = append(out, u)
		}
	}
	return out, rows.Err()
}

func (db *DB) SeedEndpointForTest(scanID, url string) error {
	_, err := db.conn.Exec(`INSERT INTO endpoints (scan_id, url, method, normalized_url) VALUES (?, ?, 'GET', ?)`, scanID, url, url)
	return err
}

func (db *DB) ListDueScheduledScans(now time.Time) ([]ScheduledScanRow, error) {
	rows, err := db.conn.Query(`
SELECT id, cron_expression, config_json, enabled, COALESCE(next_run_at,''), created_at
FROM scheduled_scans WHERE enabled = 1 AND (next_run_at IS NULL OR next_run_at <= ?)`, now.Format(time.RFC3339))
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

func (db *DB) MarkScheduleDue(id, ts string) error {
	_, err := db.conn.Exec(`UPDATE scheduled_scans SET next_run_at = ? WHERE id = ?`, ts, id)
	return err
}

func (db *DB) StartScheduledRun(scheduleID string) (int64, error) {
	res, err := db.conn.Exec(`INSERT INTO scheduled_scan_runs (schedule_id, status) VALUES (?, 'running')`, scheduleID)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (db *DB) FinishScheduledRun(runID int64, scanID, status string) error {
	_, err := db.conn.Exec(`UPDATE scheduled_scan_runs SET scan_id = ?, status = ?, finished_at = datetime('now') WHERE id = ?`,
		scanID, status, runID)
	return err
}

func (db *DB) UpdateScheduledNextRun(id, next string) error {
	_, err := db.conn.Exec(`UPDATE scheduled_scans SET next_run_at = ? WHERE id = ?`, next, id)
	return err
}

func (db *DB) SaveWorkspace(id, name, workspaceJSON string) error {
	_, err := db.conn.Exec(`
INSERT INTO workspaces (id, name, workspace_json) VALUES (?, ?, ?)
ON CONFLICT(id) DO UPDATE SET name=excluded.name, workspace_json=excluded.workspace_json`, id, name, workspaceJSON)
	return err
}

func (db *DB) SaveWorkspaceMember(workspaceID, memberJSON string) error {
	_, err := db.conn.Exec(`INSERT INTO team_members (workspace_id, member_json) VALUES (?, ?)`, workspaceID, memberJSON)
	return err
}

func (db *DB) SaveWorkspaceAudit(workspaceID, action, actor, details string) error {
	entry, _ := json.Marshal(map[string]string{"action": action, "actor": actor, "details": details})
	_, err := db.conn.Exec(`INSERT INTO audit_log_entries (workspace_id, entry_json) VALUES (?, ?)`, workspaceID, string(entry))
	return err
}

func (db *DB) ListWorkspaceMembers(workspaceID string) ([]string, error) {
	rows, err := db.conn.Query(`SELECT member_json FROM team_members WHERE workspace_id = ?`, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var raw string
		if rows.Scan(&raw) == nil {
			out = append(out, raw)
		}
	}
	return out, rows.Err()
}

func (db *DB) WorkspacePermissionAllowed(workspaceID, email, perm string) bool {
	_ = workspaceID
	_ = email
	_ = perm
	// Workspace membership is not implemented yet. Do not turn the unfinished
	// multi-user surface into an authorization bypass.
	return false
}
