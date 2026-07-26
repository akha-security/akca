package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	_ "modernc.org/sqlite"
)

var requiredTables = []string{
	"scans",
	"targets",
	"scope_rules",
	"endpoints",
	"endpoint_intelligence",
	"parameters",
	"request_records",
	"response_records",
	"waf_profiles",
	"tech_fingerprints",
	"fuzz_results",
	"oast_callbacks",
	"findings",
	"finding_groups",
	"root_cause_clusters",
	"evidence",
	"reports",
	"logs",
	"payload_outcome_history",
	"auth_profiles",
	"role_profiles",
	"encrypted_secret_refs",
	"scan_checkpoints",
	"resume_state",
	"health_snapshots",
	"baseline_profiles",
	"error_fingerprints",
	"rule_pack_versions",
	"payload_pack_versions",
	"pack_artifacts",
	"distributed_jobs",
	"policy_evaluations",
	"browser_worker_health",
	"benchmark_results",
	"learning_profiles",
	"waf_learning_profiles",
	"waf_bypass_results",
	"cve_catalog",
	"component_inventory",
	"component_cve_matches",
	"verification_observations",
	"application_states",
	"state_transitions",
	"runtime_traces",
	"endpoint_observation_sources",
	"shadow_api_diffs",
	"user_finding_annotations",
	"scheduled_scans",
	"scheduled_scan_runs",
	"comparison_scan_diffs",
	"proxy_intercept_sessions",
	"proxy_traffic_records",
	"command_center_requests",
	"payload_library_items",
	"api_key_validation_results",
	"keyboard_shortcuts",
	"timeline_events",
	"workspaces",
	"team_members",
	"workspace_invitations",
	"audit_log_entries",
	"shared_findings",
	"schema_migrations",
}

type DB struct {
	conn *sql.DB
}

func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// The engine now runs scans on a background goroutine while UI queries are
	// served concurrently, so the DB is accessed from multiple goroutines.
	// SQLite allows a single writer; serialize through one connection and wait
	// on locks instead of failing with "database is locked".
	conn.SetMaxOpenConns(1)
	conn.SetMaxIdleConns(1)
	// PRAGMA busy_timeout and foreign_keys are connection-local. Replacing the
	// only connection during a long scan silently loses those guarantees, so
	// keep it for the DB lifetime.
	conn.SetConnMaxLifetime(0)
	conn.SetConnMaxIdleTime(0)
	if _, err := conn.Exec(`PRAGMA foreign_keys = ON;`); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if _, err := conn.Exec(`PRAGMA busy_timeout = 30000;`); err != nil {
		_ = conn.Close()
		return nil, err
	}
	// WAL improves read/write concurrency; best-effort since some filesystems
	// (network/synced folders) reject it.
	_, _ = conn.Exec(`PRAGMA journal_mode = WAL;`)
	return &DB{conn: conn}, nil
}

func (db *DB) Close() error {
	return db.conn.Close()
}

func (db *DB) Conn() *sql.DB {
	return db.conn
}

func (db *DB) Migrate() error {
	if err := db.ensureMigrationTable(); err != nil {
		return err
	}
	for _, m := range sortedMigrations() {
		applied, err := db.isApplied(m.Version)
		if err != nil {
			return err
		}
		if applied {
			continue
		}
		tx, err := db.conn.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(m.Up); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %d up failed: %w", m.Version, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(version, description) VALUES (?, ?)`, m.Version, m.Description); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) Rollback(targetVersion int) error {
	migrations := sortedMigrations()
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].Version > migrations[j].Version })
	for _, m := range migrations {
		if m.Version <= targetVersion {
			break
		}
		applied, err := db.isApplied(m.Version)
		if err != nil {
			return err
		}
		if !applied {
			continue
		}
		if m.Down == "" {
			return fmt.Errorf("migration %d has no down script", m.Version)
		}
		tx, err := db.conn.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(m.Down); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %d down failed: %w", m.Version, err)
		}
		if _, err := tx.Exec(`DELETE FROM schema_migrations WHERE version = ?`, m.Version); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) CurrentVersion() (int, error) {
	row := db.conn.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`)
	var v int
	if err := row.Scan(&v); err != nil {
		return 0, err
	}
	return v, nil
}

func (db *DB) Tables() ([]string, error) {
	rows, err := db.conn.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		tables = append(tables, name)
	}
	return tables, rows.Err()
}

func (db *DB) HasAllRequiredTables() (bool, []string, error) {
	tables, err := db.Tables()
	if err != nil {
		return false, nil, err
	}
	set := make(map[string]struct{}, len(tables))
	for _, t := range tables {
		set[t] = struct{}{}
	}
	var missing []string
	for _, req := range requiredTables {
		if _, ok := set[req]; !ok {
			missing = append(missing, req)
		}
	}
	return len(missing) == 0, missing, nil
}

func (db *DB) ensureMigrationTable() error {
	_, err := db.conn.Exec(`
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  description TEXT NOT NULL,
  applied_at TEXT NOT NULL DEFAULT (datetime('now'))
);`)
	return err
}

func (db *DB) isApplied(version int) (bool, error) {
	row := db.conn.QueryRow(`SELECT 1 FROM schema_migrations WHERE version = ?`, version)
	var one int
	err := row.Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func RequiredTables() []string {
	out := make([]string, len(requiredTables))
	copy(out, requiredTables)
	sort.Strings(out)
	return out
}

func DataDir() (string, error) {
	return ResolveDataDir()
}

func DefaultDBPath() (string, error) {
	dir, err := DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "akca.db"), nil
}

func quoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}
