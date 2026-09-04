package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
)

type ParameterTarget struct {
	EndpointURL  string
	Method       string
	Parameter    string
	Location     string
	BodyTemplate string
	ContentType  string
	Headers      map[string]string
}

func (db *DB) ListParameterTargets(scanID string, limit int) ([]ParameterTarget, error) {
	baseQuery := `
SELECT e.url, e.method, p.name, p.location,
       COALESCE(json_extract(e.discovery_trail_json, '$.request_template.body'), ''),
       COALESCE(json_extract(e.discovery_trail_json, '$.request_template.content_type'), ''),
       COALESCE(json_extract(e.discovery_trail_json, '$.request_template.headers'), '{}')
FROM parameters p
JOIN endpoints e ON e.id = p.endpoint_id
WHERE e.scan_id = ?
  AND COALESCE(json_extract(e.discovery_trail_json, '$.request_template.response_status'), 0) NOT IN (404, 410)
ORDER BY p.priority DESC, p.id ASC`
	var rows *sql.Rows
	var err error
	if limit > 0 {
		rows, err = db.conn.Query(baseQuery+" LIMIT ?", scanID, limit)
	} else {
		rows, err = db.conn.Query(baseQuery, scanID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ParameterTarget, 0, limit)
	for rows.Next() {
		var t ParameterTarget
		var headersJSON string
		if err := rows.Scan(&t.EndpointURL, &t.Method, &t.Parameter, &t.Location, &t.BodyTemplate, &t.ContentType, &headersJSON); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(headersJSON), &t.Headers)
		out = append(out, t)
	}
	return out, rows.Err()
}

func selectParameterTargetsBalanced(all []ParameterTarget, limit int) []ParameterTarget {
	if limit <= 0 || len(all) == 0 {
		return nil
	}
	if len(all) <= limit {
		return all
	}
	byHost := map[string][]ParameterTarget{}
	hostOrder := make([]string, 0)
	for _, t := range all {
		host := endpointHost(t.EndpointURL)
		if _, ok := byHost[host]; !ok {
			hostOrder = append(hostOrder, host)
		}
		byHost[host] = append(byHost[host], t)
	}
	sort.Strings(hostOrder)
	out := make([]ParameterTarget, 0, limit)
	idx := make([]int, len(hostOrder))
	for len(out) < limit {
		added := false
		for i, host := range hostOrder {
			if idx[i] >= len(byHost[host]) {
				continue
			}
			out = append(out, byHost[host][idx[i]])
			idx[i]++
			added = true
			if len(out) >= limit {
				break
			}
		}
		if !added {
			break
		}
	}
	return out
}

func (db *DB) SaveReflectionProfile(scanID string, profile interface{}) error {
	return db.SaveReflectionProfileContext(context.Background(), scanID, profile)
}

func (db *DB) SaveReflectionProfileContext(ctx context.Context, scanID string, profile interface{}) error {
	b, err := json.Marshal(profile)
	if err != nil {
		return err
	}
	type fields struct {
		EndpointURL string `json:"endpoint_url"`
		Method      string `json:"method"`
		Parameter   string `json:"parameter"`
	}
	var f fields
	_ = json.Unmarshal(b, &f)
	_, err = db.execWriteContext(ctx, `
INSERT INTO baseline_profiles (scan_id, endpoint_url, method, baseline_json)
VALUES (?, ?, ?, ?)`,
		scanID, f.EndpointURL, f.Method, string(b),
	)
	return err
}

func (db *DB) ListReflectionProfileJSON(scanID string, limit int) ([]string, error) {
	query := `SELECT baseline_json FROM baseline_profiles WHERE scan_id = ? ORDER BY id DESC`
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
	var out []string
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		out = append(out, raw)
	}
	return out, rows.Err()
}

func (db *DB) LoadPayloadGenerationJSON(name string) (string, error) {
	var raw string
	err := db.conn.QueryRow(`SELECT payload_json FROM payload_library_items WHERE name = ? ORDER BY id DESC LIMIT 1`, name).Scan(&raw)
	return raw, err
}

func (db *DB) SaveGeneratedPayloads(scanID, endpointURL, parameter string, result interface{}) error {
	return db.SaveGeneratedPayloadsContext(context.Background(), scanID, endpointURL, parameter, result)
}

func (db *DB) SaveGeneratedPayloadsContext(ctx context.Context, scanID, endpointURL, parameter string, result interface{}) error {
	b, err := json.Marshal(result)
	if err != nil {
		return err
	}
	name := endpointURL + "::" + parameter
	_, err = db.execWriteContext(ctx, `
INSERT INTO payload_library_items (name, payload_json)
VALUES (?, ?)`, name, string(b))
	return err
}

func (db *DB) LoadLearningProfile(domain, endpointURL string) (LearningProfileData, error) {
	row := db.conn.QueryRow(`
SELECT profile_json FROM learning_profiles
WHERE domain = ? AND (endpoint_url = ? OR endpoint_url IS NULL OR endpoint_url = '')
ORDER BY CASE WHEN endpoint_url = ? THEN 0 ELSE 1 END, id DESC
LIMIT 1`, domain, endpointURL, endpointURL)
	var raw string
	if err := row.Scan(&raw); err != nil {
		return LearningProfileData{}, nil
	}
	var lp LearningProfileData
	_ = json.Unmarshal([]byte(raw), &lp)
	return lp, nil
}

func (db *DB) SaveLearningProfile(domain, endpointURL string, profile interface{}) error {
	b, err := json.Marshal(profile)
	if err != nil {
		return err
	}
	_, err = db.execWrite(`
INSERT INTO learning_profiles (domain, endpoint_url, profile_json)
VALUES (?, ?, ?)`, domain, endpointURL, string(b))
	return err
}

type LearningProfileData struct {
	Worked        []string `json:"worked"`
	Blocked       []string `json:"blocked"`
	Noisy         []string `json:"noisy"`
	FalsePositive []string `json:"false_positive"`
}

func (db *DB) GetTechFingerprint(scanID, host string) (TechFingerprintData, error) {
	row := db.conn.QueryRow(`
SELECT fingerprint_json FROM tech_fingerprints
WHERE scan_id = ? AND host = ?
ORDER BY id DESC LIMIT 1`, scanID, host)
	var raw string
	if err := row.Scan(&raw); err != nil {
		return TechFingerprintData{}, err
	}
	var fp TechFingerprintData
	_ = json.Unmarshal([]byte(raw), &fp)
	return fp, nil
}

func (db *DB) GetWAFProfile(scanID, host string) (WAFProfileData, error) {
	row := db.conn.QueryRow(`
SELECT profile_json FROM waf_profiles
WHERE scan_id = ? AND host = ?
ORDER BY id DESC LIMIT 1`, scanID, host)
	var raw string
	if err := row.Scan(&raw); err != nil {
		return WAFProfileData{}, err
	}
	var fp WAFProfileData
	_ = json.Unmarshal([]byte(raw), &fp)
	return fp, nil
}

type TechFingerprintData struct {
	BackendLanguage string   `json:"backend_language"`
	Framework       string   `json:"framework"`
	Database        string   `json:"database"`
	ServerCDN       string   `json:"server_cdn"`
	JSFramework     string   `json:"js_framework"`
	Hints           []string `json:"hints"`
}

type WAFProfileData struct {
	Vendor                  string `json:"vendor"`
	CautiousModeRecommended bool   `json:"cautious_mode_recommended"`
}
