package storage

import (
	"encoding/json"
)

func (db *DB) SaveOASTCallback(scanID, payloadID string, record interface{}) error {
	b, err := json.Marshal(record)
	if err != nil {
		return err
	}
	type fields struct {
		Protocol    string `json:"protocol"`
		SourceIP    string `json:"source_ip"`
		Strength    int    `json:"protocol_strength"`
		Correlation struct {
			Token string `json:"correlation_token"`
		} `json:"correlation"`
	}
	var f fields
	_ = json.Unmarshal(b, &f)
	_, err = db.conn.Exec(`
INSERT INTO oast_callbacks (
  scan_id, payload_id, protocol, source_ip, callback_json, correlation_token, protocol_strength
)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(scan_id, correlation_token)
  WHERE correlation_token IS NOT NULL AND correlation_token <> ''
DO UPDATE SET
  payload_id = excluded.payload_id,
  protocol = excluded.protocol,
  source_ip = excluded.source_ip,
  callback_json = excluded.callback_json,
  protocol_strength = excluded.protocol_strength,
  received_at = datetime('now')
WHERE excluded.protocol_strength > oast_callbacks.protocol_strength`,
		scanID, payloadID, f.Protocol, f.SourceIP, string(b), f.Correlation.Token, f.Strength,
	)
	return err
}

func (db *DB) UpgradeFindingConfidenceOAST(correlation interface{}) (bool, error) {
	b, err := json.Marshal(correlation)
	if err != nil {
		return false, err
	}
	type fields struct {
		ScanID    string `json:"scan_id"`
		FindingID int64  `json:"finding_id"`
		Endpoint  string `json:"endpoint_url"`
		VulnClass string `json:"vuln_class"`
		PayloadID string `json:"payload_id"`
	}
	var f fields
	if err := json.Unmarshal(b, &f); err != nil {
		return false, err
	}
	if f.ScanID == "" {
		return false, nil
	}

	if f.FindingID > 0 {
		res, err := db.conn.Exec(`
UPDATE findings SET confidence = 'Confirmed', evidence_json = ?
WHERE id = ? AND scan_id = ? AND evidence_json LIKE ?`,
			string(b), f.FindingID, f.ScanID, "%"+f.PayloadID+"%",
		)
		if err != nil {
			return false, err
		}
		n, _ := res.RowsAffected()
		return n > 0, nil
	}

	// Never upgrade "the latest finding on the endpoint". A callback without an
	// exact finding ID is materialized as a new evidence-first finding after
	// the drain phase.
	return false, nil
}

func (db *DB) CountOASTCallbacks(scanID string) (int, error) {
	row := db.conn.QueryRow(`SELECT COUNT(*) FROM oast_callbacks WHERE scan_id = ?`, scanID)
	var n int
	if err := row.Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func (db *DB) HasOASTCallback(scanID, payloadID string) (bool, error) {
	row := db.conn.QueryRow(`SELECT 1 FROM oast_callbacks WHERE scan_id = ? AND payload_id = ? LIMIT 1`, scanID, payloadID)
	var one int
	if err := row.Scan(&one); err != nil {
		return false, nil
	}
	return true, nil
}

func (db *DB) HasFindingForOAST(scanID, endpoint, vulnClass, payloadID string) (bool, error) {
	row := db.conn.QueryRow(`
SELECT 1 FROM findings
WHERE scan_id = ? AND endpoint_url = ? AND vuln_class = ?
  AND evidence_json LIKE ? LIMIT 1`,
		scanID, endpoint, vulnClass, "%"+payloadID+"%")
	var one int
	if err := row.Scan(&one); err != nil {
		return false, nil
	}
	return true, nil
}
