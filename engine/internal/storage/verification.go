package storage

import "encoding/json"

func (db *DB) SaveVerificationResult(scanID string, candidate, result interface{}) error {
	payload := map[string]interface{}{
		"candidate": candidate,
		"result":    result,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = db.conn.Exec(`
INSERT INTO payload_outcome_history (scan_id, payload_hash, outcome, details_json)
VALUES (?, 'verification', 'verified', ?)`, scanID, string(b))
	return err
}

func (db *DB) SaveParameterBaseline(scanID string, baseline interface{}) error {
	b, err := json.Marshal(baseline)
	if err != nil {
		return err
	}
	type fields struct {
		Key struct {
			EndpointURL string `json:"endpoint_url"`
			Method      string `json:"method"`
		} `json:"key"`
	}
	var f fields
	_ = json.Unmarshal(b, &f)
	_, err = db.conn.Exec(`
INSERT INTO baseline_profiles (scan_id, endpoint_url, method, baseline_json)
VALUES (?, ?, ?, ?)`, scanID, f.Key.EndpointURL, f.Key.Method, string(b))
	return err
}
