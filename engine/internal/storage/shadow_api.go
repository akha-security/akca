package storage

type EndpointObservation struct {
	URL    string `json:"url"`
	Method string `json:"method"`
	Source string `json:"source"`
}

type ShadowAPIDiff struct {
	ID               int64  `json:"id,omitempty"`
	ScanID           string `json:"scan_id"`
	Kind             string `json:"kind"`
	Method           string `json:"method"`
	Path             string `json:"path"`
	DocumentedMethod string `json:"documented_method,omitempty"`
	ObservedMethod   string `json:"observed_method,omitempty"`
	Source           string `json:"source,omitempty"`
	Detail           string `json:"detail"`
	CreatedAt        string `json:"created_at,omitempty"`
}

func (db *DB) ListEndpointObservations(scanID string) ([]EndpointObservation, error) {
	rows, err := db.conn.Query(`
SELECT url, method, source
FROM endpoint_observation_sources
WHERE scan_id = ?
ORDER BY id`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EndpointObservation
	for rows.Next() {
		var row EndpointObservation
		if err := rows.Scan(&row.URL, &row.Method, &row.Source); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (db *DB) ReplaceShadowAPIDiffs(scanID string, diffs []ShadowAPIDiff) error {
	if err := db.EnsureScan(scanID); err != nil {
		return err
	}
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM shadow_api_diffs WHERE scan_id = ?`, scanID); err != nil {
		return err
	}
	for _, diff := range diffs {
		if _, err := tx.Exec(`
INSERT INTO shadow_api_diffs
  (scan_id, kind, method, path, documented_method, observed_method, source, detail)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			scanID, diff.Kind, diff.Method, diff.Path, diff.DocumentedMethod,
			diff.ObservedMethod, diff.Source, diff.Detail); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) ListShadowAPIDiffs(scanID, kind string, limit int) ([]ShadowAPIDiff, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := db.conn.Query(`
SELECT id, scan_id, kind, method, path, COALESCE(documented_method,''),
       COALESCE(observed_method,''), COALESCE(source,''), detail, created_at
FROM shadow_api_diffs
WHERE scan_id = ? AND (? = '' OR kind = ?)
ORDER BY id
LIMIT ?`, scanID, kind, kind, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ShadowAPIDiff
	for rows.Next() {
		var row ShadowAPIDiff
		if err := rows.Scan(&row.ID, &row.ScanID, &row.Kind, &row.Method, &row.Path,
			&row.DocumentedMethod, &row.ObservedMethod, &row.Source, &row.Detail, &row.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
