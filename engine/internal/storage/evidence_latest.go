package storage

func (db *DB) LatestEvidenceJSON(scanID, kind string) (string, error) {
	var body string
	err := db.conn.QueryRow(`SELECT evidence_json FROM evidence WHERE scan_id=? AND evidence_type=? ORDER BY id DESC LIMIT 1`, scanID, kind).Scan(&body)
	return body, err
}
