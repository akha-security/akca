package storage

// ListAuthBlockedEndpoints returns endpoints whose crawl response was 401 or 403.
func (db *DB) ListAuthBlockedEndpoints(scanID string, limit int) ([]Fuzz403Entry, error) {
	if limit <= 0 {
		limit = 2000
	}
	rows, err := db.conn.Query(`
SELECT DISTINCT url, method FROM endpoints
WHERE scan_id = ? AND (
  discovery_trail_json LIKE '%"response_status":401%'
  OR discovery_trail_json LIKE '%"response_status":403%'
)
LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Fuzz403Entry
	for rows.Next() {
		var e Fuzz403Entry
		if err := rows.Scan(&e.URL, &e.Method); err != nil {
			return nil, err
		}
		if e.Method == "" {
			e.Method = "GET"
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
