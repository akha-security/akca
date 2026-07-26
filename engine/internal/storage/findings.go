package storage

import (
	"database/sql"
	"encoding/json"
	"strings"
)

const embeddedEvidenceMarker = "\n\nevidence: "

// ExtractEmbeddedEvidence pulls the JSON evidence blob the engine appends to
// finding descriptions when evidence_json was not stored separately.
func ExtractEmbeddedEvidence(description string) string {
	idx := strings.Index(description, embeddedEvidenceMarker)
	if idx < 0 {
		return ""
	}
	return strings.TrimSpace(description[idx+len(embeddedEvidenceMarker):])
}

func (db *DB) ListScriptEndpoints(scanID string, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := db.conn.Query(`
SELECT DISTINCT url FROM endpoints
WHERE scan_id = ? AND (
  url LIKE '%.js' OR url LIKE '%.mjs' OR url LIKE '%.cjs' OR
  discovery_source IN ('script', 'js_bundle', 'js_analyzer', 'inline_js')
)
AND COALESCE(json_extract(discovery_trail_json, '$.request_template.response_status'), 0) NOT IN (404, 410)
LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var urls []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		if strings.HasSuffix(strings.ToLower(u), ".js") || strings.Contains(strings.ToLower(u), ".js?") {
			urls = append(urls, u)
		}
	}
	return urls, rows.Err()
}

// JSDiscoveredEndpoint is a JS-derived API endpoint with its HTTP method for re-crawl.
type JSDiscoveredEndpoint struct {
	URL         string
	Method      string
	Body        string
	ContentType string
	Headers     map[string]string
}

// ListJSDiscoveredAPIURLs returns non-script endpoints found via JavaScript analysis.
func (db *DB) ListJSDiscoveredAPIURLs(scanID string, limit int) ([]string, error) {
	eps, err := db.ListJSDiscoveredAPIEndpoints(scanID, limit)
	if err != nil {
		return nil, err
	}
	urls := make([]string, 0, len(eps))
	for _, ep := range eps {
		urls = append(urls, ep.URL)
	}
	return urls, nil
}

// ListJSDiscoveredAPIEndpoints returns JS-discovered endpoints with HTTP methods.
func (db *DB) ListJSDiscoveredAPIEndpoints(scanID string, limit int) ([]JSDiscoveredEndpoint, error) {
	if limit <= 0 {
		limit = 400
	}
	rows, err := db.conn.Query(`
SELECT url, method, COALESCE(discovery_trail_json,'') FROM endpoints
WHERE scan_id = ? AND discovery_source IN ('js_analyzer', 'js_bundle', 'inline_js', 'js_ast')
AND url NOT LIKE '%.js' AND url NOT LIKE '%.mjs' AND url NOT LIKE '%.cjs'
AND url NOT LIKE '%.js?%'
LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []JSDiscoveredEndpoint
	for rows.Next() {
		var u, method, trail string
		if err := rows.Scan(&u, &method, &trail); err != nil {
			return nil, err
		}
		if method == "" {
			method = "GET"
		}
		ep := JSDiscoveredEndpoint{URL: u, Method: strings.ToUpper(method)}
		if trail != "" {
			var doc struct {
				RequestTemplate *struct {
					Body        string            `json:"body"`
					ContentType string            `json:"content_type"`
					Headers     map[string]string `json:"headers"`
				} `json:"request_template"`
			}
			if json.Unmarshal([]byte(trail), &doc) == nil && doc.RequestTemplate != nil {
				ep.Body = doc.RequestTemplate.Body
				ep.ContentType = doc.RequestTemplate.ContentType
				ep.Headers = doc.RequestTemplate.Headers
			}
		}
		out = append(out, ep)
	}
	return out, rows.Err()
}

// SaveFinding persists a finding and returns its row id. When evidenceJSON is
// non-empty it is stored on the finding row so the UI can render HTTP proof even
// if the separate evidence table lookup fails.
func (db *DB) SaveFinding(scanID, title, severity, vulnClass, description, endpoint, parameter string, confidence float64, evidenceJSON string) (int64, error) {
	res, err := db.conn.Exec(`
INSERT INTO findings (scan_id, title, description, severity, confidence, confidence_score, vuln_class, endpoint_url, parameter, evidence_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		scanID, title, description, severity, confidenceLabel(confidence), confidence, vulnClass, endpoint, parameter, evidenceJSON,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func confidenceLabel(score float64) string {
	switch {
	case score >= 0.9:
		return "Confirmed"
	case score >= 0.75:
		return "HighConfidence"
	case score >= 0.55:
		return "Potential"
	default:
		return "NeedsManualReview"
	}
}

func (db *DB) GetFinding(findingID int64) (FindingRecord, error) {
	var rec FindingRecord
	err := db.conn.QueryRow(`
SELECT id, title, COALESCE(summary,''), COALESCE(description,''), severity, confidence,
       COALESCE(confidence_score,0), vuln_class, COALESCE(endpoint_url,''),
       COALESCE(parameter,''), COALESCE(evidence_json,''), created_at
FROM findings WHERE id = ?`, findingID).Scan(
		&rec.ID, &rec.Title, &rec.Summary, &rec.Description, &rec.Severity, &rec.Confidence,
		&rec.ConfidenceScore, &rec.VulnClass, &rec.EndpointURL, &rec.Parameter,
		&rec.EvidenceJSON, &rec.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return rec, sql.ErrNoRows
	}
	return rec, err
}
