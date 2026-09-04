package storage

import (
	"encoding/json"
	"fmt"
)

const maxTrailResponseBytes = 4096

func (db *DB) SaveDiscoveredEndpoint(scanID string, ep interface{}) error {
	b, err := json.Marshal(ep)
	if err != nil {
		return err
	}
	b = compactDiscoveryTrail(b)
	type endpointFields struct {
		URL           string  `json:"url"`
		Method        string  `json:"method"`
		NormalizedURL string  `json:"normalized_url"`
		Source        string  `json:"source"`
		Confidence    float64 `json:"confidence"`
		WhyDiscovered string  `json:"why_discovered"`
	}
	var fields endpointFields
	if err := json.Unmarshal(b, &fields); err != nil {
		return err
	}
	if fields.Method == "" {
		fields.Method = "GET"
	}
	if fields.NormalizedURL == "" {
		fields.NormalizedURL = fields.URL
	}
	_ = db.EnsureScan(scanID)

	var existingTrail string
	_ = db.conn.QueryRow(`SELECT discovery_trail_json FROM endpoints WHERE scan_id = ? AND url = ? AND method = ?`,
		scanID, fields.URL, fields.Method).Scan(&existingTrail)

	trail := mergeDiscoveryTrail(existingTrail, string(b))
	_, err = db.conn.Exec(`
INSERT OR IGNORE INTO endpoints (scan_id, url, method, normalized_url, discovery_source, discovery_confidence, discovery_trail_json)
VALUES (?, ?, ?, ?, ?, ?, ?)`,
		scanID, fields.URL, fields.Method, fields.NormalizedURL,
		fields.Source, fields.Confidence, trail,
	)
	if err != nil {
		return fmt.Errorf("save discovered endpoint: %w", err)
	}
	_, err = db.conn.Exec(`
UPDATE endpoints SET discovery_trail_json = ?, discovery_confidence = MAX(discovery_confidence, ?)
WHERE scan_id = ? AND url = ? AND method = ?`,
		trail, fields.Confidence, scanID, fields.URL, fields.Method,
	)
	if err != nil {
		return fmt.Errorf("update endpoint trail: %w", err)
	}
	_, err = db.conn.Exec(`
INSERT OR IGNORE INTO endpoint_observation_sources (scan_id, url, method, source)
VALUES (?, ?, ?, ?)`, scanID, fields.URL, fields.Method, fields.Source)
	if err != nil {
		return fmt.Errorf("save endpoint observation source: %w", err)
	}
	return nil
}

func mergeDiscoveryTrail(existingJSON, incomingJSON string) string {
	if existingJSON == "" {
		return incomingJSON
	}
	var existingDoc map[string]interface{}
	var incomingDoc map[string]interface{}
	if json.Unmarshal([]byte(existingJSON), &existingDoc) != nil ||
		json.Unmarshal([]byte(incomingJSON), &incomingDoc) != nil {
		return incomingJSON
	}
	existingTmpl, existHasTmpl := existingDoc["request_template"].(map[string]interface{})
	incomingTmpl, incHasTmpl := incomingDoc["request_template"].(map[string]interface{})
	if existHasTmpl && len(existingTmpl) > 0 {
		if !incHasTmpl || len(incomingTmpl) == 0 {
			incomingDoc["request_template"] = existingTmpl
		} else {
			if existBody, _ := existingTmpl["body"].(string); existBody != "" {
				if incBody, _ := incomingTmpl["body"].(string); incBody == "" {
					incomingTmpl["body"] = existBody
				}
			}
			if existCT, _ := existingTmpl["content_type"].(string); existCT != "" {
				if incCT, _ := incomingTmpl["content_type"].(string); incCT == "" {
					incomingTmpl["content_type"] = existCT
				}
			}
			incomingDoc["request_template"] = incomingTmpl
		}
		if merged, err := json.Marshal(incomingDoc); err == nil {
			return string(merged)
		}
	}
	return incomingJSON
}

func compactDiscoveryTrail(raw []byte) []byte {
	var doc map[string]interface{}
	if json.Unmarshal(raw, &doc) != nil {
		return raw
	}
	tmpl, ok := doc["request_template"].(map[string]interface{})
	if !ok {
		return raw
	}
	if body, ok := tmpl["response_body"].(string); ok && len(body) > maxTrailResponseBytes {
		tmpl["response_body"] = body[:maxTrailResponseBytes] + "...[truncated]"
		doc["request_template"] = tmpl
		out, err := json.Marshal(doc)
		if err == nil {
			return out
		}
	}
	return raw
}

func (db *DB) GetEndpointID(scanID, url, method string) (int64, error) {
	if method == "" {
		method = "GET"
	}
	row := db.conn.QueryRow(`SELECT id FROM endpoints WHERE scan_id = ? AND url = ? AND method = ? LIMIT 1`, scanID, url, method)
	var id int64
	if err := row.Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func (db *DB) CountEndpoints(scanID string) (int, error) {
	row := db.conn.QueryRow(`SELECT COUNT(*) FROM endpoints WHERE scan_id = ?`, scanID)
	var count int
	if err := row.Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// endpointDiscoveryOrderSQL prioritizes write/API endpoints before query-heavy
// GET pages so hidden-parameter discovery spends its budget on native POST/
// JSON/form surfaces before speculative query probing.
const endpointDiscoveryOrderSQL = `
ORDER BY
  CASE WHEN upper(method) IN ('POST','PUT','PATCH','DELETE') THEN 0 ELSE 1 END,
  CASE WHEN COALESCE(json_extract(discovery_trail_json, '$.request_template.body'), '') <> '' THEN 0 ELSE 1 END,
  CASE WHEN instr(lower(url), '/api/') > 0 OR instr(lower(url), '/graphql') > 0 OR instr(lower(url), '/v1/') > 0 THEN 0 ELSE 1 END,
  CASE WHEN instr(lower(url), '?') > 0 THEN 0 ELSE 1 END,
  CASE WHEN instr(lower(url), '.js') > 0 OR instr(lower(url), '.css') > 0 OR instr(lower(url), '.png') > 0 OR instr(lower(url), '.jpg') > 0 THEN 1 ELSE 0 END,
  id ASC`
