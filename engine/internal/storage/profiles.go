package storage

import (
	"encoding/json"
	"fmt"
)

type EndpointPlan struct {
	URL                string
	Method             string
	EndpointType       string
	AuthRequired       bool
	StateChanging      bool
	RiskTags           []string
	RecommendedModules []string
}

func (db *DB) ListEndpointPlans(scanID string) (map[string]EndpointPlan, error) {
	rows, err := db.conn.Query(`
SELECT e.url, e.method, COALESCE(ei.endpoint_type, ''), COALESCE(ei.auth_required, 0),
       COALESCE(ei.state_changing, 0), COALESCE(ei.risk_tags_json, '[]'),
       COALESCE(ei.recommended_modules_json, '[]')
FROM endpoints e
JOIN endpoint_intelligence ei ON ei.endpoint_id = e.id
WHERE e.scan_id = ?
ORDER BY ei.id DESC`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]EndpointPlan{}
	for rows.Next() {
		var plan EndpointPlan
		var auth, state int
		var risksRaw, modulesRaw string
		if err := rows.Scan(&plan.URL, &plan.Method, &plan.EndpointType, &auth, &state, &risksRaw, &modulesRaw); err != nil {
			return nil, err
		}
		plan.AuthRequired = auth != 0
		plan.StateChanging = state != 0
		_ = json.Unmarshal([]byte(risksRaw), &plan.RiskTags)
		_ = json.Unmarshal([]byte(modulesRaw), &plan.RecommendedModules)
		key := plan.URL + "::" + plan.Method
		if _, exists := out[key]; !exists {
			out[key] = plan
		}
	}
	return out, rows.Err()
}

func (db *DB) SaveWAFProfile(scanID string, profile any) error {
	b, err := json.Marshal(profile)
	if err != nil {
		return err
	}
	host := extractHost(profile)
	_, err = db.conn.Exec(
		`INSERT INTO waf_profiles (scan_id, host, vendor, profile_json) VALUES (?, ?, ?, ?)`,
		scanID, host, extractVendor(profile), string(b),
	)
	return err
}

func (db *DB) SaveTechFingerprint(scanID string, fp any) error {
	b, err := json.Marshal(fp)
	if err != nil {
		return err
	}
	host := extractHost(fp)
	_, err = db.conn.Exec(
		`INSERT INTO tech_fingerprints (scan_id, host, fingerprint_json) VALUES (?, ?, ?)`,
		scanID, host, string(b),
	)
	return err
}

func extractHost(v any) string {
	m, ok := v.(map[string]interface{})
	if ok {
		if h, ok := m["host"].(string); ok {
			return h
		}
	}
	type hoster struct {
		Host string `json:"host"`
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	var h hoster
	if json.Unmarshal(b, &h) == nil {
		return h.Host
	}
	return ""
}

func extractVendor(v any) string {
	type vendorer struct {
		Vendor string `json:"vendor"`
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	var vv vendorer
	if json.Unmarshal(b, &vv) == nil {
		return vv.Vendor
	}
	return ""
}

func (db *DB) SaveEndpointIntelligence(scanID, url, method string, intel any) (int64, error) {
	tx, err := db.conn.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.Exec(
		`INSERT INTO endpoints (scan_id, url, method, normalized_url) VALUES (?, ?, ?, ?)`,
		scanID, url, method, url,
	)
	if err != nil {
		return 0, err
	}
	endpointID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}

	b, err := json.Marshal(intel)
	if err != nil {
		return 0, err
	}
	_, err = tx.Exec(
		`INSERT INTO endpoint_intelligence (endpoint_id, endpoint_type, auth_required, state_changing, content_type, risk_tags_json, recommended_modules_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		endpointID,
		extractStringField(intel, "endpoint_type"),
		boolToInt(extractBoolField(intel, "auth_required")),
		boolToInt(extractBoolField(intel, "state_changing")),
		extractStringField(intel, "content_type"),
		extractJSONField(intel, "risk_tags"),
		extractJSONField(intel, "recommended_modules"),
	)
	if err != nil {
		return 0, fmt.Errorf("save endpoint intelligence: %w", err)
	}
	_ = b
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return endpointID, nil
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func extractStringField(v any, field string) string {
	b, _ := json.Marshal(v)
	var m map[string]interface{}
	if json.Unmarshal(b, &m) != nil {
		return ""
	}
	if s, ok := m[field].(string); ok {
		return s
	}
	return ""
}

func extractBoolField(v any, field string) bool {
	b, _ := json.Marshal(v)
	var m map[string]interface{}
	if json.Unmarshal(b, &m) != nil {
		return false
	}
	if s, ok := m[field].(bool); ok {
		return s
	}
	return false
}

func extractJSONField(v any, field string) string {
	b, _ := json.Marshal(v)
	var m map[string]interface{}
	if json.Unmarshal(b, &m) != nil {
		return "[]"
	}
	if val, ok := m[field]; ok {
		out, err := json.Marshal(val)
		if err == nil {
			return string(out)
		}
	}
	return "[]"
}
