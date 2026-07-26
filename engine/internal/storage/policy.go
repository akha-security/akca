package storage

func (db *DB) SavePolicyEvaluation(currentScanID, previousScanID string, passed bool, evaluationJSON string) error {
	var passedInt int
	if passed {
		passedInt = 1
	}
	var previous any
	if previousScanID != "" {
		previous = previousScanID
	}
	_, err := db.conn.Exec(`
INSERT INTO policy_evaluations
  (current_scan_id, previous_scan_id, passed, evaluation_json)
VALUES (?, ?, ?, ?)`, currentScanID, previous, passedInt, evaluationJSON)
	return err
}
