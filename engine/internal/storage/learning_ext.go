package storage

import "encoding/json"

func (db *DB) ListLearningDomains() ([]string, error) {
	rows, err := db.conn.Query(`SELECT DISTINCT domain FROM learning_profiles ORDER BY domain ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (db *DB) SaveWAFLearningProfile(domain string, profile interface{}) error {
	b, err := json.Marshal(profile)
	if err != nil {
		return err
	}
	_, err = db.conn.Exec(`INSERT INTO waf_learning_profiles (domain, profile_json) VALUES (?, ?)`, domain, b)
	return err
}

func (db *DB) LoadWAFLearningProfile(domain string) (string, error) {
	var raw string
	err := db.conn.QueryRow(`
SELECT profile_json FROM waf_learning_profiles
WHERE domain = ? ORDER BY id DESC LIMIT 1`, domain).Scan(&raw)
	return raw, err
}

func (db *DB) SaveWAFBypassResult(scanID, strategyID, resultJSON string) error {
	_, err := db.conn.Exec(
		`INSERT INTO waf_bypass_results (scan_id, strategy_id, result_json) VALUES (?, ?, ?)`,
		scanID, strategyID, resultJSON,
	)
	return err
}
