package storage

import (
	"database/sql"
	"encoding/json"
)

type DiscoveryRequestTemplate struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
}

type DiscoveryEndpoint struct {
	ID              int64
	URL             string
	Method          string
	RequestTemplate DiscoveryRequestTemplate
}

func (db *DB) ListDiscoveryEndpoints(scanID string, limit int) ([]DiscoveryEndpoint, error) {
	query := `SELECT id, url, method, COALESCE(discovery_trail_json, '') FROM endpoints
WHERE scan_id = ? 
	  AND COALESCE(json_extract(discovery_trail_json, '$.request_template.response_status'), 0) NOT IN (404, 410) ` + endpointDiscoveryOrderSQL
	var rows *sql.Rows
	var err error
	if limit > 0 {
		rows, err = db.conn.Query(query+` LIMIT ?`, scanID, limit)
	} else {
		rows, err = db.conn.Query(query, scanID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]DiscoveryEndpoint, 0)
	for rows.Next() {
		var ep DiscoveryEndpoint
		var trailJSON string
		if err := rows.Scan(&ep.ID, &ep.URL, &ep.Method, &trailJSON); err != nil {
			return nil, err
		}
		var trail struct {
			RequestTemplate *DiscoveryRequestTemplate `json:"request_template"`
		}
		if trailJSON != "" && json.Unmarshal([]byte(trailJSON), &trail) == nil && trail.RequestTemplate != nil {
			ep.RequestTemplate = *trail.RequestTemplate
		}
		out = append(out, ep)
	}
	return out, rows.Err()
}

func (db *DB) SaveParameter(endpointID int64, name, location string, priority int) error {
	_, err := db.conn.Exec(`
INSERT INTO parameters (endpoint_id, name, location, priority) VALUES (?, ?, ?, ?)
ON CONFLICT(endpoint_id, name, location) DO UPDATE SET priority = MAX(parameters.priority, excluded.priority)`,
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
