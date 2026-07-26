package storage

import (
	"database/sql"
	"encoding/json"
)

type EvidenceLimits struct {
	Findings     int
	Groups       int
	Clusters     int
	Evidence     int
	Requests     int
	Profiles     int
	Fuzz         int
	OAST         int
	Outcomes     int
	Checkpoints  int
	Health       int
	APIKeys      int
	Observations int
}

func DefaultEvidenceLimits() EvidenceLimits {
	return EvidenceLimits{
		Findings: 500, Groups: 100, Clusters: 100, Evidence: 500, Requests: 200,
		Profiles: 50, Fuzz: 200, OAST: 100, Outcomes: 200, Checkpoints: 10,
		Health: 20, APIKeys: 50,
		Observations: 1000,
	}
}

type FindingRecord struct {
	ID              int64   `json:"id"`
	Title           string  `json:"title"`
	Summary         string  `json:"summary,omitempty"`
	Description     string  `json:"description,omitempty"`
	Severity        string  `json:"severity"`
	Confidence      string  `json:"confidence"`
	ConfidenceScore float64 `json:"confidence_score"`
	VulnClass       string  `json:"vuln_class"`
	EndpointURL     string  `json:"endpoint_url,omitempty"`
	Parameter       string  `json:"parameter,omitempty"`
	EvidenceJSON    string  `json:"evidence_json,omitempty"`
	CreatedAt       string  `json:"created_at,omitempty"`
}

type FindingGroupRecord struct {
	ID        int64  `json:"id"`
	RootCause string `json:"root_cause"`
	GroupJSON string `json:"group_json"`
	CreatedAt string `json:"created_at,omitempty"`
}

type RootCauseClusterRecord struct {
	ID          int64  `json:"id"`
	ClusterKey  string `json:"cluster_key"`
	ClusterJSON string `json:"cluster_json"`
	CreatedAt   string `json:"created_at,omitempty"`
}

type EvidenceRecord struct {
	ID           int64         `json:"id"`
	FindingID    sql.NullInt64 `json:"finding_id,omitempty"`
	EvidenceType string        `json:"evidence_type"`
	EvidenceJSON string        `json:"evidence_json"`
	CreatedAt    string        `json:"created_at,omitempty"`
}

type RequestResponseRecord struct {
	RequestID   int64  `json:"request_id"`
	Method      string `json:"method"`
	URL         string `json:"url"`
	ReqHeaders  string `json:"req_headers,omitempty"`
	ReqBody     string `json:"req_body,omitempty"`
	StatusCode  int    `json:"status_code"`
	RespHeaders string `json:"resp_headers,omitempty"`
	RespBody    string `json:"resp_body,omitempty"`
	DurationMs  int64  `json:"duration_ms"`
	CreatedAt   string `json:"created_at,omitempty"`
}

type WAFProfileRecord struct {
	Host        string `json:"host"`
	Vendor      string `json:"vendor,omitempty"`
	ProfileJSON string `json:"profile_json"`
}

type TechFingerprintRecord struct {
	Host            string `json:"host"`
	FingerprintJSON string `json:"fingerprint_json"`
}

type FuzzResultRecord struct {
	URL        string `json:"url"`
	Method     string `json:"method"`
	StatusCode int    `json:"status_code"`
	Category   string `json:"category,omitempty"`
	ResultJSON string `json:"result_json,omitempty"`
}

type OASTCallbackRecord struct {
	PayloadID    string `json:"payload_id"`
	Protocol     string `json:"protocol,omitempty"`
	SourceIP     string `json:"source_ip,omitempty"`
	CallbackJSON string `json:"callback_json"`
	ReceivedAt   string `json:"received_at,omitempty"`
}

type PayloadOutcomeRecord struct {
	PayloadHash string `json:"payload_hash"`
	Outcome     string `json:"outcome"`
	DetailsJSON string `json:"details_json,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
}

type AuthProfileRecord struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	ProfileJSON string `json:"profile_json"`
}

type RoleProfileRecord struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	AuthProfileID string `json:"auth_profile_id,omitempty"`
	ProfileJSON   string `json:"profile_json"`
}

type CheckpointRecord struct {
	CheckpointJSON string `json:"checkpoint_json"`
	CreatedAt      string `json:"created_at,omitempty"`
}

type ResumeStateRecord struct {
	StateJSON string `json:"state_json"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

type HealthSnapshotRecord struct {
	MetricsJSON string `json:"metrics_json"`
	CreatedAt   string `json:"created_at,omitempty"`
}

type APIKeyValidationRecord struct {
	Service    string `json:"service"`
	Status     string `json:"status"`
	ResultJSON string `json:"result_json"`
	CreatedAt  string `json:"created_at,omitempty"`
}

func (db *DB) GetScanConfig(scanID string) (string, error) {
	var cfg string
	err := db.conn.QueryRow(`SELECT config_json FROM scans WHERE id = ?`, scanID).Scan(&cfg)
	if err == sql.ErrNoRows {
		return "{}", nil
	}
	return cfg, err
}

func (db *DB) ListFindings(scanID string, limit, offset int) ([]FindingRecord, error) {
	rows, err := db.conn.Query(`
SELECT id, title, COALESCE(summary,''), COALESCE(description,''), severity, confidence, COALESCE(confidence_score,0), vuln_class,
       COALESCE(endpoint_url,''), COALESCE(parameter,''), COALESCE(evidence_json,''), created_at
FROM findings WHERE scan_id = ? ORDER BY id DESC LIMIT ? OFFSET ?`, scanID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanFindings(rows)
}

func (db *DB) IterateFindings(scanID string, fn func(FindingRecord) error) error {
	rows, err := db.conn.Query(`
SELECT id, title, COALESCE(summary,''), COALESCE(description,''), severity, confidence, COALESCE(confidence_score,0), vuln_class,
       COALESCE(endpoint_url,''), COALESCE(parameter,''), COALESCE(evidence_json,''), created_at
FROM findings WHERE scan_id = ? ORDER BY id ASC`, scanID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		rec, err := scanFindingRow(rows)
		if err != nil {
			return err
		}
		if err := fn(rec); err != nil {
			return err
		}
	}
	return rows.Err()
}

func scanFindings(rows *sql.Rows) ([]FindingRecord, error) {
	var out []FindingRecord
	for rows.Next() {
		rec, err := scanFindingRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func scanFindingRow(rows *sql.Rows) (FindingRecord, error) {
	var rec FindingRecord
	err := rows.Scan(&rec.ID, &rec.Title, &rec.Summary, &rec.Description, &rec.Severity, &rec.Confidence,
		&rec.ConfidenceScore, &rec.VulnClass, &rec.EndpointURL, &rec.Parameter, &rec.EvidenceJSON, &rec.CreatedAt)
	return rec, err
}

func (db *DB) ListFindingGroups(scanID string, limit int) ([]FindingGroupRecord, error) {
	rows, err := db.conn.Query(`
SELECT id, root_cause, group_json, created_at FROM finding_groups
WHERE scan_id = ? ORDER BY id DESC LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FindingGroupRecord
	for rows.Next() {
		var rec FindingGroupRecord
		if err := rows.Scan(&rec.ID, &rec.RootCause, &rec.GroupJSON, &rec.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (db *DB) ListRootCauseClusters(scanID string, limit int) ([]RootCauseClusterRecord, error) {
	rows, err := db.conn.Query(`
SELECT id, cluster_key, cluster_json, created_at FROM root_cause_clusters
WHERE scan_id = ? ORDER BY id DESC LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RootCauseClusterRecord
	for rows.Next() {
		var rec RootCauseClusterRecord
		if err := rows.Scan(&rec.ID, &rec.ClusterKey, &rec.ClusterJSON, &rec.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (db *DB) ListEvidenceRecords(scanID string, limit int) ([]EvidenceRecord, error) {
	rows, err := db.conn.Query(`
SELECT id, finding_id, evidence_type, evidence_json, created_at FROM evidence
WHERE scan_id = ? ORDER BY id DESC LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EvidenceRecord
	for rows.Next() {
		var rec EvidenceRecord
		if err := rows.Scan(&rec.ID, &rec.FindingID, &rec.EvidenceType, &rec.EvidenceJSON, &rec.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (db *DB) ListRequestResponses(scanID string, limit int) ([]RequestResponseRecord, error) {
	rows, err := db.conn.Query(`
SELECT r.id, r.method, r.url, COALESCE(r.headers_json,''), COALESCE(r.body,''),
       COALESCE(resp.status_code,0), COALESCE(resp.headers_json,''), COALESCE(resp.body,''),
       COALESCE(resp.duration_ms,0), r.created_at
FROM request_records r
LEFT JOIN response_records resp ON resp.request_id = r.id
WHERE r.scan_id = ? ORDER BY r.id DESC LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RequestResponseRecord
	for rows.Next() {
		var rec RequestResponseRecord
		if err := rows.Scan(&rec.RequestID, &rec.Method, &rec.URL, &rec.ReqHeaders, &rec.ReqBody,
			&rec.StatusCode, &rec.RespHeaders, &rec.RespBody, &rec.DurationMs, &rec.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (db *DB) ListWAFProfileRecords(scanID string, limit int) ([]WAFProfileRecord, error) {
	rows, err := db.conn.Query(`
SELECT host, COALESCE(vendor,''), profile_json FROM waf_profiles
WHERE scan_id = ? ORDER BY id DESC LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanWAFProfiles(rows)
}

func scanWAFProfiles(rows *sql.Rows) ([]WAFProfileRecord, error) {
	var out []WAFProfileRecord
	for rows.Next() {
		var rec WAFProfileRecord
		if err := rows.Scan(&rec.Host, &rec.Vendor, &rec.ProfileJSON); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (db *DB) ListTechFingerprintRecords(scanID string, limit int) ([]TechFingerprintRecord, error) {
	rows, err := db.conn.Query(`
SELECT host, fingerprint_json FROM tech_fingerprints WHERE scan_id = ? ORDER BY id DESC LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TechFingerprintRecord
	for rows.Next() {
		var rec TechFingerprintRecord
		if err := rows.Scan(&rec.Host, &rec.FingerprintJSON); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (db *DB) ListFuzzResultRecords(scanID string, limit int) ([]FuzzResultRecord, error) {
	rows, err := db.conn.Query(`
SELECT url, method, status_code, COALESCE(category,''), COALESCE(result_json,'')
FROM fuzz_results WHERE scan_id = ? AND status_code != 404 ORDER BY id DESC LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FuzzResultRecord
	for rows.Next() {
		var rec FuzzResultRecord
		if err := rows.Scan(&rec.URL, &rec.Method, &rec.StatusCode, &rec.Category, &rec.ResultJSON); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (db *DB) ListFuzzByCategory(scanID, category string, limit int) ([]FuzzResultRecord, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := db.conn.Query(`
SELECT url, method, status_code, COALESCE(category,''), COALESCE(result_json,'')
FROM fuzz_results WHERE scan_id = ? AND category = ? ORDER BY id DESC LIMIT ?`, scanID, category, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FuzzResultRecord
	for rows.Next() {
		var rec FuzzResultRecord
		if err := rows.Scan(&rec.URL, &rec.Method, &rec.StatusCode, &rec.Category, &rec.ResultJSON); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (db *DB) ListOASTCallbackRecords(scanID string, limit int) ([]OASTCallbackRecord, error) {
	rows, err := db.conn.Query(`
SELECT payload_id, COALESCE(protocol,''), COALESCE(source_ip,''), callback_json, received_at
FROM oast_callbacks WHERE scan_id = ? ORDER BY id DESC LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OASTCallbackRecord
	for rows.Next() {
		var rec OASTCallbackRecord
		if err := rows.Scan(&rec.PayloadID, &rec.Protocol, &rec.SourceIP, &rec.CallbackJSON, &rec.ReceivedAt); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (db *DB) ListPayloadOutcomeRecords(scanID string, limit int) ([]PayloadOutcomeRecord, error) {
	rows, err := db.conn.Query(`
SELECT payload_hash, outcome, COALESCE(details_json,''), created_at
FROM payload_outcome_history WHERE scan_id = ? ORDER BY id DESC LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PayloadOutcomeRecord
	for rows.Next() {
		var rec PayloadOutcomeRecord
		if err := rows.Scan(&rec.PayloadHash, &rec.Outcome, &rec.DetailsJSON, &rec.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (db *DB) GetAuthProfileRecord(scanID, id string) (AuthProfileRecord, error) {
	var rec AuthProfileRecord
	err := db.conn.QueryRow(`
SELECT id, name, profile_json FROM auth_profiles
WHERE id = ? AND (scan_id = ? OR scan_id IS NULL)
ORDER BY created_at DESC LIMIT 1`, id, scanID).Scan(&rec.ID, &rec.Name, &rec.ProfileJSON)
	return rec, err
}

func (db *DB) ListAuthProfileRecords(scanID string, limit int) ([]AuthProfileRecord, error) {
	rows, err := db.conn.Query(`
SELECT id, name, profile_json FROM auth_profiles
WHERE scan_id = ? OR scan_id IS NULL ORDER BY created_at DESC LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuthProfileRecord
	for rows.Next() {
		var rec AuthProfileRecord
		if err := rows.Scan(&rec.ID, &rec.Name, &rec.ProfileJSON); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (db *DB) ListRoleProfileRecords(scanID string, limit int) ([]RoleProfileRecord, error) {
	rows, err := db.conn.Query(`
SELECT id, name, COALESCE(auth_profile_id,''), profile_json FROM role_profiles
WHERE scan_id = ? OR scan_id IS NULL ORDER BY created_at DESC LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RoleProfileRecord
	for rows.Next() {
		var rec RoleProfileRecord
		if err := rows.Scan(&rec.ID, &rec.Name, &rec.AuthProfileID, &rec.ProfileJSON); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (db *DB) ListCheckpointRecords(scanID string, limit int) ([]CheckpointRecord, error) {
	rows, err := db.conn.Query(`
SELECT checkpoint_json, created_at FROM scan_checkpoints
WHERE scan_id = ? ORDER BY id DESC LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CheckpointRecord
	for rows.Next() {
		var rec CheckpointRecord
		if err := rows.Scan(&rec.CheckpointJSON, &rec.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (db *DB) ListResumeStateRecords(scanID string, limit int) ([]ResumeStateRecord, error) {
	rows, err := db.conn.Query(`
SELECT state_json, updated_at FROM resume_state WHERE scan_id = ? ORDER BY id DESC LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ResumeStateRecord
	for rows.Next() {
		var rec ResumeStateRecord
		if err := rows.Scan(&rec.StateJSON, &rec.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (db *DB) ListHealthSnapshotRecords(scanID string, limit int) ([]HealthSnapshotRecord, error) {
	rows, err := db.conn.Query(`
SELECT metrics_json, created_at FROM health_snapshots
WHERE scan_id = ? OR scan_id IS NULL ORDER BY id DESC LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HealthSnapshotRecord
	for rows.Next() {
		var rec HealthSnapshotRecord
		if err := rows.Scan(&rec.MetricsJSON, &rec.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (db *DB) ListAPIKeyValidationRecords(scanID string, limit int) ([]APIKeyValidationRecord, error) {
	rows, err := db.conn.Query(`
SELECT service, status, result_json, created_at FROM api_key_validation_results
WHERE scan_id = ? OR scan_id IS NULL ORDER BY id DESC LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIKeyValidationRecord
	for rows.Next() {
		var rec APIKeyValidationRecord
		if err := rows.Scan(&rec.Service, &rec.Status, &rec.ResultJSON, &rec.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (db *DB) SaveReportRecord(scanID, template, format, path, reportJSON string) error {
	_, err := db.conn.Exec(`
INSERT INTO reports (scan_id, template, format, path, report_json) VALUES (?, ?, ?, ?, ?)`,
		scanID, template, format, path, reportJSON)
	return err
}

func (db *DB) SaveFindingGroup(scanID, rootCause string, group interface{}) error {
	raw, _ := json.Marshal(group)
	_, err := db.conn.Exec(`INSERT INTO finding_groups (scan_id, root_cause, group_json) VALUES (?, ?, ?)`,
		scanID, rootCause, string(raw))
	return err
}

func (db *DB) DeleteFindingGroup(id int64) error {
	_, err := db.conn.Exec(`DELETE FROM finding_groups WHERE id = ?`, id)
	return err
}

func (db *DB) SaveRootCauseCluster(scanID, key string, cluster interface{}) error {
	raw, _ := json.Marshal(cluster)
	_, err := db.conn.Exec(`INSERT INTO root_cause_clusters (scan_id, cluster_key, cluster_json) VALUES (?, ?, ?)`,
		scanID, key, string(raw))
	return err
}

func (db *DB) SaveAPIKeyValidation(scanID, service, status string, result interface{}) error {
	raw, _ := json.Marshal(result)
	_, err := db.conn.Exec(`
INSERT INTO api_key_validation_results (scan_id, service, status, result_json) VALUES (?, ?, ?, ?)`,
		scanID, service, status, string(raw))
	return err
}

type FindingsFilter struct {
	ScanID      string
	Severities  []string
	Confidences []string
	VulnClasses []string
	FindingIDs  []int64
	SearchQuery string
	AfterID     int64
	Limit       int
	Offset      int
}

func (f FindingsFilter) normalizedLimit() int {
	if f.Limit <= 0 {
		return 500
	}
	return f.Limit
}

func (db *DB) CountFindingsFiltered(f FindingsFilter) (int, error) {
	q, args := buildFindingsQuery(f, true)
	var n int
	err := db.conn.QueryRow(q, args...).Scan(&n)
	return n, err
}

func (db *DB) ListFindingsFiltered(f FindingsFilter) ([]FindingRecord, error) {
	q, args := buildFindingsQuery(f, false)
	rows, err := db.conn.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanFindings(rows)
}

func (db *DB) IterateFindingsFiltered(f FindingsFilter, fn func(FindingRecord) error) error {
	f.Limit = 0
	f.Offset = 0
	q, args := buildFindingsQuery(f, false)
	rows, err := db.conn.Query(q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		rec, err := scanFindingRow(rows)
		if err != nil {
			return err
		}
		if err := fn(rec); err != nil {
			return err
		}
	}
	return rows.Err()
}

func buildFindingsQuery(f FindingsFilter, countOnly bool) (string, []interface{}) {
	var args []interface{}
	selectClause := `SELECT f.id, f.title, COALESCE(f.summary,''), COALESCE(f.description,''), f.severity, f.confidence, COALESCE(f.confidence_score,0), f.vuln_class,
       COALESCE(f.endpoint_url,''), COALESCE(f.parameter,''), COALESCE(f.evidence_json,''), f.created_at`
	if countOnly {
		selectClause = `SELECT COUNT(*)`
	}
	q := selectClause + ` FROM findings f`
	if f.SearchQuery != "" {
		q += ` INNER JOIN findings_fts fts ON fts.rowid = f.id WHERE f.scan_id = ? AND findings_fts MATCH ?`
		args = append(args, f.ScanID, f.SearchQuery)
	} else {
		q += ` WHERE f.scan_id = ?`
		args = append(args, f.ScanID)
	}
	if len(f.FindingIDs) > 0 {
		q += ` AND f.id IN (` + placeholders(len(f.FindingIDs)) + `)`
		for _, id := range f.FindingIDs {
			args = append(args, id)
		}
	}
	if len(f.Severities) > 0 {
		q += ` AND f.severity IN (` + placeholders(len(f.Severities)) + `)`
		for _, s := range f.Severities {
			args = append(args, s)
		}
	}
	if len(f.Confidences) > 0 {
		q += ` AND f.confidence IN (` + placeholders(len(f.Confidences)) + `)`
		for _, c := range f.Confidences {
			args = append(args, c)
		}
	}
	if len(f.VulnClasses) > 0 {
		q += ` AND f.vuln_class IN (` + placeholders(len(f.VulnClasses)) + `)`
		for _, v := range f.VulnClasses {
			args = append(args, v)
		}
	}
	if f.AfterID > 0 {
		q += ` AND f.id > ?`
		args = append(args, f.AfterID)
	}
	if !countOnly {
		q += ` ORDER BY f.id ASC`
		if f.Limit > 0 {
			q += ` LIMIT ? OFFSET ?`
			args = append(args, f.normalizedLimit(), f.Offset)
		}
	}
	return q, args
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	out := "?"
	for i := 1; i < n; i++ {
		out += ",?"
	}
	return out
}

type DashboardMetrics struct {
	TotalFindings int            `json:"total_findings"`
	BySeverity    map[string]int `json:"by_severity"`
	ByConfidence  map[string]int `json:"by_confidence"`
	ByVulnClass   map[string]int `json:"by_vuln_class"`
	EvidenceCount int            `json:"evidence_count"`
	OASTCallbacks int            `json:"oast_callbacks"`
	EndpointCount int            `json:"endpoint_count"`
}

func (db *DB) DashboardMetrics(scanID string) (DashboardMetrics, error) {
	m := DashboardMetrics{
		BySeverity:   map[string]int{},
		ByConfidence: map[string]int{},
		ByVulnClass:  map[string]int{},
	}
	_ = db.conn.QueryRow(`SELECT COUNT(*) FROM findings WHERE scan_id = ?`, scanID).Scan(&m.TotalFindings)
	rows, err := db.conn.Query(`SELECT severity, COUNT(*) FROM findings WHERE scan_id = ? GROUP BY severity`, scanID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var sev string
			var n int
			if rows.Scan(&sev, &n) == nil {
				m.BySeverity[sev] = n
			}
		}
	}
	rows, err = db.conn.Query(`SELECT confidence, COUNT(*) FROM findings WHERE scan_id = ? GROUP BY confidence`, scanID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var c string
			var n int
			if rows.Scan(&c, &n) == nil {
				m.ByConfidence[c] = n
			}
		}
	}
	rows, err = db.conn.Query(`SELECT vuln_class, COUNT(*) FROM findings WHERE scan_id = ? GROUP BY vuln_class`, scanID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var vc string
			var n int
			if rows.Scan(&vc, &n) == nil {
				m.ByVulnClass[vc] = n
			}
		}
	}
	_ = db.conn.QueryRow(`SELECT COUNT(*) FROM evidence WHERE scan_id = ?`, scanID).Scan(&m.EvidenceCount)
	_ = db.conn.QueryRow(`SELECT COUNT(*) FROM oast_callbacks WHERE scan_id = ?`, scanID).Scan(&m.OASTCallbacks)
	_ = db.conn.QueryRow(`SELECT COUNT(*) FROM endpoints WHERE scan_id = ?`, scanID).Scan(&m.EndpointCount)
	return m, nil
}

func (db *DB) SearchFindings(scanID, query string, limit, offset int) ([]FindingRecord, error) {
	return db.ListFindingsFiltered(FindingsFilter{
		ScanID: scanID, SearchQuery: query, Limit: limit, Offset: offset,
	})
}

func (db *DB) GetEvidenceForFinding(scanID string, findingID int64) ([]EvidenceRecord, error) {
	rows, err := db.conn.Query(`
SELECT id, finding_id, evidence_type, evidence_json, created_at FROM evidence
WHERE scan_id = ? AND finding_id = ? ORDER BY id ASC`, scanID, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EvidenceRecord
	for rows.Next() {
		var rec EvidenceRecord
		if err := rows.Scan(&rec.ID, &rec.FindingID, &rec.EvidenceType, &rec.EvidenceJSON, &rec.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (db *DB) SeedFindingForTest(scanID, title, severity, confidence, vulnClass, description, endpoint string) error {
	_, err := db.conn.Exec(`
INSERT INTO findings (scan_id, title, description, severity, confidence, vuln_class, endpoint_url)
VALUES (?, ?, ?, ?, ?, ?, ?)`, scanID, title, description, severity, confidence, vulnClass, endpoint)
	return err
}
