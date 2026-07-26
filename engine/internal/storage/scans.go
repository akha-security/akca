package storage

func (db *DB) EnsureScan(scanID string) error {
	_, err := db.conn.Exec(
		`INSERT OR IGNORE INTO scans (id, status, config_json) VALUES (?, 'running', '{}')`,
		scanID,
	)
	return err
}
