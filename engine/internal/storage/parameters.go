package storage

type DiscoveryEndpoint struct {
	ID     int64
	URL    string
	Method string
}

func (db *DB) ListDiscoveryEndpoints(scanID string, limit int) ([]DiscoveryEndpoint, error) {
	if limit <= 0 {
		limit = 200
	}
	query := `SELECT id, url, method FROM endpoints 
WHERE scan_id = ? 
  AND COALESCE(json_extract(discovery_trail_json, '$.request_template.response_status'), 0) NOT IN (404, 410) ` + endpointDiscoveryOrderSQL + ` LIMIT ?`
	rows, err := db.conn.Query(query, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]DiscoveryEndpoint, 0, limit)
	for rows.Next() {
		var ep DiscoveryEndpoint
		if err := rows.Scan(&ep.ID, &ep.URL, &ep.Method); err != nil {
			return nil, err
		}
		out = append(out, ep)
	}
	return out, rows.Err()
}

func (db *DB) SaveParameter(endpointID int64, name, location string, priority int) error {
	_, err := db.conn.Exec(`
INSERT OR IGNORE INTO parameters (endpoint_id, name, location, priority) VALUES (?, ?, ?, ?)`,
		endpointID, name, location, priority,
	)
	return err
}

func (db *DB) CountParameters(endpointID int64) (int, error) {
	row := db.conn.QueryRow(`SELECT COUNT(*) FROM parameters WHERE endpoint_id = ?`, endpointID)
	var n int
	if err := row.Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}
