package storage

import "encoding/json"

func (db *DB) SaveBypassResult(scanID, strategyID string, result interface{}) error {
	b, err := json.Marshal(result)
	if err != nil {
		return err
	}
	_, err = db.conn.Exec(`
INSERT INTO waf_bypass_results (scan_id, strategy_id, result_json)
VALUES (?, ?, ?)`, scanID, strategyID, string(b))
	return err
}

func (db *DB) SaveEvidence(scanID, evidenceType, evidenceJSON string) error {
	_, err := db.conn.Exec(`
INSERT INTO evidence (scan_id, evidence_type, evidence_json)
VALUES (?, ?, ?)`, scanID, evidenceType, evidenceJSON)
	return err
}

func (db *DB) SaveEvidenceForFinding(scanID string, findingID int64, evidenceType, evidenceJSON string) error {
	_, err := db.conn.Exec(`
INSERT INTO evidence (scan_id, finding_id, evidence_type, evidence_json)
VALUES (?, ?, ?, ?)`, scanID, findingID, evidenceType, evidenceJSON)
	return err
}

func (db *DB) GetFindingScanID(findingID int64) (string, error) {
	var scanID string
	err := db.conn.QueryRow(`SELECT scan_id FROM findings WHERE id = ?`, findingID).Scan(&scanID)
	return scanID, err
}
