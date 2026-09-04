package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/akha-security/akca/engine/internal/findingtext"
)

type EndpointRow struct {
	ID                  int64   `json:"id"`
	URL                 string  `json:"url"`
	Method              string  `json:"method"`
	DiscoverySource     string  `json:"discovery_source,omitempty"`
	DiscoveryConfidence float64 `json:"discovery_confidence,omitempty"`
	ParameterCount      int     `json:"parameter_count"`
	FindingCount        int     `json:"finding_count"`
	RiskLevel           string  `json:"risk_level"`
	Status              string  `json:"status"`
}

type EndpointQuery struct {
	ScanID   string
	Search   string
	Method   string
	Status   string
	SortBy   string
	SortDesc bool
	Limit    int
	Cursor   int64
}

type FindingRow struct {
	ID          int64  `json:"id"`
	Title       string `json:"title"`
	Summary     string `json:"summary"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	VulnClass   string `json:"vuln_class"`
	EndpointURL string `json:"endpoint_url"`
	Parameter   string `json:"parameter"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
}

type FindingQuery struct {
	ScanID      string
	Search      string
	Severities  []string
	Confidences []string
	VulnClasses []string
	Status      string
	SortBy      string
	SortDesc    bool
	Limit       int
	Cursor      int64
}

type EndpointDetail struct {
	EndpointRow
	IntelligenceJSON string   `json:"intelligence_json,omitempty"`
	DiscoveryTrail   string   `json:"discovery_trail_json,omitempty"`
	Parameters       []string `json:"parameters"`
	LinkedFindingIDs []int64  `json:"linked_finding_ids"`
	ModulesRun       []string `json:"modules_run"`
	RawRequest       string   `json:"raw_request,omitempty"`
	RawResponse      string   `json:"raw_response,omitempty"`
	CurlCommand      string   `json:"curl_command,omitempty"`
	StatusCode       int      `json:"status_code,omitempty"`
}

type FindingDetail struct {
	FindingRow
	Impact            string          `json:"impact"`
	Remediation       string          `json:"remediation"`
	ConfidenceExplain string          `json:"confidence_explanation"`
	EvidenceJSON      string          `json:"evidence_json,omitempty"`
	RelatedFindingIDs []int64         `json:"related_finding_ids"`
	Annotations       []AnnotationRow `json:"annotations"`
}

type AnnotationRow struct {
	ID             int64  `json:"id"`
	FindingID      int64  `json:"finding_id"`
	AnnotationType string `json:"annotation_type"`
	Notes          string `json:"notes,omitempty"`
	AnnotatedBy    string `json:"annotated_by,omitempty"`
	CreatedAt      string `json:"created_at"`
}

type EvidenceLazy struct {
	ID           int64  `json:"id"`
	EvidenceType string `json:"evidence_type"`
	HasBody      bool   `json:"has_body"`
	Preview      string `json:"preview,omitempty"`
}

type EvidenceBody struct {
	EvidenceJSON string `json:"evidence_json"`
	ReqHeaders   string `json:"req_headers,omitempty"`
	ReqBody      string `json:"req_body,omitempty"`
	RespHeaders  string `json:"resp_headers,omitempty"`
	RespBody     string `json:"resp_body,omitempty"`
	Screenshot   string `json:"screenshot_ref,omitempty"`
	DOMSnapshot  string `json:"dom_snapshot_ref,omitempty"`
	// Burp-style raw request/response text and a concise attack summary.
	RawRequest       string                        `json:"raw_request,omitempty"`
	RawResponse      string                        `json:"raw_response,omitempty"`
	Module           string                        `json:"module,omitempty"`
	Signal           string                        `json:"signal,omitempty"`
	Payload          string                        `json:"payload,omitempty"`
	Parameter        string                        `json:"parameter,omitempty"`
	Location         string                        `json:"location,omitempty"`
	ResponseMarkers  []string                      `json:"response_markers,omitempty"`
	ProofSummary     string                        `json:"proof_summary,omitempty"`
	Method           string                        `json:"method,omitempty"`
	URL              string                        `json:"url,omitempty"`
	StatusCode       int                           `json:"status_code,omitempty"`
	DurationMs       int64                         `json:"duration_ms,omitempty"`
	OASTURL          string                        `json:"oast_url,omitempty"`
	CurlCommand      string                        `json:"curl_command,omitempty"`
	ConfidenceScore  float64                       `json:"confidence_score,omitempty"`
	ProofType        string                        `json:"proof_type,omitempty"`
	ProofPolicy      string                        `json:"proof_policy_version,omitempty"`
	ProofSatisfied   bool                          `json:"proof_satisfied"`
	DowngradeReasons []string                      `json:"downgrade_reasons,omitempty"`
	UpgradeReasons   []string                      `json:"upgrade_reasons,omitempty"`
	SemanticDelta    map[string]interface{}        `json:"semantic_delta,omitempty"`
	Observations     []VerificationObservationView `json:"observations,omitempty"`
}

type VerificationObservationView struct {
	ID              string `json:"id"`
	Role            string `json:"role"`
	Attempt         int    `json:"attempt"`
	IdentityID      string `json:"identity_id,omitempty"`
	RequestID       string `json:"request_id,omitempty"`
	RequestMethod   string `json:"request_method,omitempty"`
	RequestURL      string `json:"request_url,omitempty"`
	RequestHash     string `json:"request_hash,omitempty"`
	ResponseHash    string `json:"response_hash,omitempty"`
	NormalizedHash  string `json:"normalized_hash,omitempty"`
	StatusCode      int    `json:"status_code,omitempty"`
	DurationMs      int64  `json:"duration_ms,omitempty"`
	StateBeforeHash string `json:"state_before_hash,omitempty"`
	StateAfterHash  string `json:"state_after_hash,omitempty"`
	OASTPayloadID   string `json:"oast_payload_id,omitempty"`
	RuntimeTraceID  string `json:"runtime_trace_id,omitempty"`
	RuntimeSink     string `json:"runtime_sink,omitempty"`
	RuntimeSafe     bool   `json:"runtime_safe,omitempty"`
}

type TargetMapNode struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Type     string `json:"type"`
	Risk     string `json:"risk"`
	Count    int    `json:"count"`
	ParentID string `json:"parent_id,omitempty"`
}

type FuzzDashboard struct {
	ByCategory   map[string]int     `json:"by_category"`
	ByStatusCode map[string]int     `json:"by_status_code"`
	Total        int                `json:"total"`
	Notable      []FuzzResultRecord `json:"notable"`
}

type Bypass403Row struct {
	URL          string   `json:"url"`
	AttemptCount int      `json:"attempt_count"`
	SuccessCount int      `json:"success_count"`
	Techniques   []string `json:"techniques"`
	EvidenceJSON string   `json:"evidence_json,omitempty"`
}

type TimelineRow struct {
	ID        int64  `json:"id"`
	EventType string `json:"event_type"`
	Summary   string `json:"summary"`
	EventJSON string `json:"event_json,omitempty"`
	CreatedAt string `json:"created_at"`
}

func (db *DB) ListEndpointsUI(q EndpointQuery) ([]EndpointRow, int64, error) {
	if q.Limit <= 0 {
		q.Limit = 50
	}
	if q.Limit > 2000 {
		q.Limit = 2000
	}
	// Stable keyset pagination uses monotonic e.id; display sort is applied client-side.
	sortCol := "e.id"
	order := "ASC"
	if q.SortDesc {
		order = "DESC"
	}
	where := `WHERE e.scan_id = ?`
	args := []interface{}{q.ScanID, q.ScanID}
	if q.Cursor > 0 {
		if q.SortDesc {
			where += ` AND e.id < ?`
		} else {
			where += ` AND e.id > ?`
		}
		args = append(args, q.Cursor)
	}
	if q.Search != "" {
		where += ` AND e.url LIKE ?`
		args = append(args, "%"+q.Search+"%")
	}
	if q.Method != "" {
		where += ` AND e.method = ?`
		args = append(args, q.Method)
	}
	query := fmt.Sprintf(`
SELECT e.id, e.url, e.method, COALESCE(e.discovery_source,''), COALESCE(e.discovery_confidence,0),
       COALESCE(pc.cnt,0), COALESCE(fc.cnt,0),
       CASE WHEN COALESCE(fc.cnt,0) > 0 THEN 'vulnerable' WHEN COALESCE(pc.cnt,0) > 0 THEN 'tested' ELSE 'discovered' END AS status,
       CASE WHEN COALESCE(fc.cnt,0) > 0 THEN 'high' WHEN COALESCE(pc.cnt,0) > 0 THEN 'medium' ELSE 'low' END AS risk_level
FROM endpoints e
LEFT JOIN (SELECT endpoint_id, COUNT(*) cnt FROM parameters GROUP BY endpoint_id) pc ON pc.endpoint_id = e.id
LEFT JOIN (SELECT endpoint_url, COUNT(*) cnt FROM findings WHERE scan_id = ? GROUP BY endpoint_url) fc ON fc.endpoint_url = e.url
%s ORDER BY %s %s LIMIT ?`, where, sortCol, order)
	args = append(args, q.Limit)

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []EndpointRow
	var lastID int64
	for rows.Next() {
		var row EndpointRow
		if err := rows.Scan(&row.ID, &row.URL, &row.Method, &row.DiscoverySource, &row.DiscoveryConfidence,
			&row.ParameterCount, &row.FindingCount, &row.Status, &row.RiskLevel); err != nil {
			return nil, 0, err
		}
		if q.Status != "" && row.Status != q.Status {
			continue
		}
		out = append(out, row)
		lastID = row.ID
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	var next int64
	if len(out) >= q.Limit {
		next = lastID
	}
	return out, next, nil
}

func (db *DB) GetEndpointDetailUI(endpointID int64) (EndpointDetail, error) {
	var d EndpointDetail
	err := db.conn.QueryRow(`
SELECT e.id, e.url, e.method, COALESCE(e.discovery_source,''), COALESCE(e.discovery_confidence,0),
       COALESCE(e.discovery_trail_json,''),
       COALESCE(ei.endpoint_type,'') || '|' || COALESCE(ei.risk_tags_json,'') || '|' || COALESCE(ei.recommended_modules_json,'')
FROM endpoints e
LEFT JOIN endpoint_intelligence ei ON ei.endpoint_id = e.id
WHERE e.id = ?`, endpointID).Scan(
		&d.ID, &d.URL, &d.Method, &d.DiscoverySource, &d.DiscoveryConfidence,
		&d.DiscoveryTrail, &d.IntelligenceJSON,
	)
	if err != nil {
		return d, err
	}
	rows, err := db.conn.Query(`SELECT name FROM parameters WHERE endpoint_id = ?`, endpointID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var name string
			if rows.Scan(&name) == nil {
				d.Parameters = append(d.Parameters, name)
			}
		}
	}
	rows, err = db.conn.Query(`SELECT id FROM findings WHERE endpoint_url = ? ORDER BY id DESC LIMIT 20`, d.URL)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id int64
			if rows.Scan(&id) == nil {
				d.LinkedFindingIDs = append(d.LinkedFindingIDs, id)
			}
		}
	}
	if d.FindingCount == 0 {
		d.FindingCount = len(d.LinkedFindingIDs)
	}
	d.ModulesRun = []string{"crawler", "fuzzing", "vuln_modules"}
	if d.FindingCount > 0 {
		d.RiskLevel = "high"
		d.Status = "vulnerable"
	} else if len(d.Parameters) > 0 {
		d.RiskLevel = "medium"
		d.Status = "tested"
	} else {
		d.RiskLevel = "low"
		d.Status = "discovered"
	}
	attachEndpointHTTPPreview(&d)
	return d, nil
}

func attachEndpointHTTPPreview(d *EndpointDetail) {
	if d.DiscoveryTrail == "" {
		return
	}
	var trail struct {
		RequestTemplate *struct {
			Method                string            `json:"method"`
			URL                   string            `json:"url"`
			Headers               map[string]string `json:"headers"`
			Body                  string            `json:"body"`
			ContentType           string            `json:"content_type"`
			ResponseStatus        int               `json:"response_status"`
			ResponseHeaders       map[string]string `json:"response_headers"`
			ResponseBody          string            `json:"response_body"`
			FetchedViaGETFallback bool              `json:"fetched_via_get_fallback"`
		} `json:"request_template"`
	}
	if json.Unmarshal([]byte(d.DiscoveryTrail), &trail) != nil || trail.RequestTemplate == nil {
		return
	}
	rt := trail.RequestTemplate
	reqH := headerLinesFromMap(rt.Headers)
	respH := headerLinesFromMap(rt.ResponseHeaders)
	d.StatusCode = rt.ResponseStatus
	d.RawRequest = buildRawRequest(rt.Method, rt.URL, reqH, rt.Body)
	respBody := rt.ResponseBody
	if rt.FetchedViaGETFallback {
		note := "# Note: POST was attempted; response below was fetched via GET fallback for content extraction.\n"
		respBody = note + respBody
	}
	d.RawResponse = buildRawResponse(rt.ResponseStatus, respH, respBody)
	d.CurlCommand = buildCurlCommand(rt.Method, rt.URL, reqH, rt.Body)
}

func headerLinesFromMap(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(m[k])
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n")
}

func (db *DB) ListFindingsUI(q FindingQuery) ([]FindingRow, int64, error) {
	if q.Limit <= 0 {
		q.Limit = 50
	}
	ff := FindingsFilter{
		ScanID: q.ScanID, Severities: q.Severities, Confidences: q.Confidences,
		VulnClasses: q.VulnClasses, SearchQuery: q.Search, AfterID: q.Cursor, Limit: q.Limit,
	}
	recs, err := db.ListFindingsFiltered(ff)
	if err != nil {
		return nil, 0, err
	}
	var out []FindingRow
	var lastID int64
	for _, rec := range recs {
		status := "open"
		row := FindingRow{
			ID: rec.ID, Title: findingtext.DisplayTitle(rec.VulnClass, rec.Title), Summary: rec.Summary, Description: rec.Description,
			Severity: rec.Severity, Confidence: rec.Confidence, VulnClass: rec.VulnClass,
			EndpointURL: rec.EndpointURL, Parameter: rec.Parameter, Status: status, CreatedAt: rec.CreatedAt,
		}
		ann, _ := db.LatestAnnotation(rec.ID)
		if ann.AnnotationType != "" {
			row.Status = ann.AnnotationType
		}
		if q.Status != "" && row.Status != q.Status {
			continue
		}
		out = append(out, row)
		lastID = rec.ID
	}
	var next int64
	if len(out) >= q.Limit {
		next = lastID
	}
	return out, next, nil
}

func stripDescriptionForUI(description string) string {
	idx := strings.Index(description, "\n\nevidence:")
	if idx >= 0 {
		return strings.TrimSpace(description[:idx])
	}
	return strings.TrimSpace(description)
}

func (db *DB) GetFindingDetailUI(findingID int64) (FindingDetail, error) {
	var d FindingDetail
	err := db.conn.QueryRow(`
SELECT id, title, COALESCE(summary,''), COALESCE(description,''), severity, confidence, vuln_class,
       COALESCE(endpoint_url,''), COALESCE(parameter,''), COALESCE(evidence_json,''), created_at
FROM findings WHERE id = ?`, findingID).Scan(
		&d.ID, &d.Title, &d.Summary, &d.Description, &d.Severity, &d.Confidence, &d.VulnClass,
		&d.EndpointURL, &d.Parameter, &d.EvidenceJSON, &d.CreatedAt,
	)
	if err != nil {
		return d, err
	}
	d.Status = "open"
	d.Impact = defaultImpactText(d.Severity)
	d.Remediation = defaultRemediationText(d.VulnClass)
	d.ConfidenceExplain = confidenceExplainText(d.Confidence)
	if d.Summary == "" {
		d.Summary = d.Description
	}
	if d.Summary == "" {
		d.Summary = "Automated finding — review evidence before submission."
	}
	if d.EvidenceJSON == "" {
		d.EvidenceJSON = ExtractEmbeddedEvidence(d.Description)
	}
	if d.Parameter == "" && d.EvidenceJSON != "" {
		ev := parseEvidenceBody(d.EvidenceJSON)
		if ev.Parameter != "" {
			d.Parameter = ev.Parameter
		}
	}
	d.Title = findingtext.DisplayTitle(d.VulnClass, d.Title)
	d.Description = stripDescriptionForUI(d.Description)
	anns, _ := db.ListAnnotations(findingID)
	d.Annotations = anns
	if len(anns) > 0 {
		d.Status = anns[0].AnnotationType
	}
	rows, err := db.conn.Query(`
SELECT id FROM findings WHERE vuln_class = ? AND endpoint_url = ? AND id != ? LIMIT 10`,
		d.VulnClass, d.EndpointURL, findingID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id int64
			if rows.Scan(&id) == nil {
				d.RelatedFindingIDs = append(d.RelatedFindingIDs, id)
			}
		}
	}
	return d, nil
}

func (db *DB) ListEvidenceLazy(scanID string, findingID int64) ([]EvidenceLazy, error) {
	if findingID > 0 {
		var findingScanID, evidenceJSON, description string
		_ = db.conn.QueryRow(`
SELECT scan_id, COALESCE(evidence_json,''), COALESCE(description,'')
FROM findings WHERE id = ?`, findingID).Scan(&findingScanID, &evidenceJSON, &description)
		if findingScanID != "" {
			scanID = findingScanID
		}

		rows, err := db.conn.Query(`
SELECT id, evidence_type, evidence_json FROM evidence
WHERE finding_id = ? ORDER BY id ASC LIMIT 50`, findingID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := scanEvidenceLazyRows(rows)
		if len(out) > 0 {
			return out, nil
		}

		if evidenceJSON == "" {
			evidenceJSON = ExtractEmbeddedEvidence(description)
		}
		if evidenceJSON != "" {
			return []EvidenceLazy{{
				ID:           -findingID,
				EvidenceType: "http_proof",
				HasBody:      true,
				Preview:      evidencePreview(evidenceJSON),
			}}, nil
		}
		return nil, nil
	}

	if scanID == "" {
		return nil, nil
	}
	rows, err := db.conn.Query(`
SELECT id, evidence_type, evidence_json FROM evidence
WHERE scan_id = ? ORDER BY id ASC LIMIT 50`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvidenceLazyRows(rows), rows.Err()
}

func scanEvidenceLazyRows(rows *sql.Rows) []EvidenceLazy {
	var out []EvidenceLazy
	for rows.Next() {
		var id int64
		var typ, raw string
		if err := rows.Scan(&id, &typ, &raw); err != nil {
			continue
		}
		out = append(out, EvidenceLazy{
			ID: id, EvidenceType: typ, HasBody: len(raw) > 0, Preview: evidencePreview(raw),
		})
	}
	return out
}

func evidencePreview(raw string) string {
	if len(raw) <= 120 {
		return raw
	}
	return raw[:120] + "…"
}

func (db *DB) LoadEvidenceBody(evidenceID int64) (EvidenceBody, error) {
	if evidenceID < 0 {
		return db.loadEvidenceFromFinding(-evidenceID)
	}
	var body EvidenceBody
	var raw string
	err := db.conn.QueryRow(`SELECT evidence_json FROM evidence WHERE id = ?`, evidenceID).Scan(&raw)
	if err != nil {
		return body, err
	}
	return parseEvidenceBody(raw), nil
}

func (db *DB) loadEvidenceFromFinding(findingID int64) (EvidenceBody, error) {
	var body EvidenceBody
	var evidenceJSON, description string
	err := db.conn.QueryRow(`
SELECT COALESCE(evidence_json,''), COALESCE(description,'') FROM findings WHERE id = ?`, findingID).Scan(&evidenceJSON, &description)
	if err != nil {
		return body, err
	}
	if evidenceJSON == "" {
		evidenceJSON = ExtractEmbeddedEvidence(description)
	}
	if evidenceJSON == "" {
		return body, sql.ErrNoRows
	}
	return parseEvidenceBody(evidenceJSON), nil
}

func parseEvidenceBody(raw string) EvidenceBody {
	body := EvidenceBody{EvidenceJSON: raw}
	var parsed map[string]interface{}
	_ = json.Unmarshal([]byte(raw), &parsed)

	// Legacy flat keys (kept for backward compatibility).
	if v, ok := parsed["req_body"].(string); ok {
		body.ReqBody = v
	}
	if v, ok := parsed["resp_body"].(string); ok {
		body.RespBody = v
	}
	if v, ok := parsed["req_headers"].(string); ok {
		body.ReqHeaders = v
	}
	if v, ok := parsed["resp_headers"].(string); ok {
		body.RespHeaders = v
	}
	if v, ok := parsed["screenshot_ref"].(string); ok {
		body.Screenshot = v
	}
	if v, ok := parsed["dom_snapshot_ref"].(string); ok {
		body.DOMSnapshot = v
	}

	// Module findings store evidence as nested request/response records. Parse
	// them into Burp-style raw request/response text plus an attack summary so
	// the UI can show exactly what payload was sent and what came back.
	if s, ok := parsed["module"].(string); ok {
		body.Module = s
	}
	if s, ok := parsed["signal"].(string); ok {
		body.Signal = s
	}
	if s, ok := parsed["oast_url"].(string); ok {
		body.OASTURL = s
	}
	// Passive secret findings use a compact evidence shape rather than the
	// active module request/response envelope. Promote those fields into the
	// same technical-evidence view used by reports and the UI.
	if s, ok := parsed["secret_kind"].(string); ok && body.Signal == "" {
		body.Module = "secret_exposure"
		body.Signal = s
	}
	if s, ok := parsed["secret_value"].(string); ok && body.Payload == "" {
		body.Payload = s
	}
	if s, ok := parsed["source_url"].(string); ok && body.URL == "" {
		body.URL = s
		body.Method = "GET"
		body.Location = "response_body"
	}
	if pl, ok := parsed["payload"].(map[string]interface{}); ok {
		if v, ok := pl["value"].(string); ok {
			body.Payload = v
		}
	}
	if v, ok := parsed["parameter"].(string); ok {
		body.Parameter = v
	}
	if v, ok := parsed["location"].(string); ok {
		body.Location = v
	}
	if raw, ok := parsed["response_markers"].([]interface{}); ok {
		for _, item := range raw {
			if s, ok := item.(string); ok && s != "" {
				body.ResponseMarkers = append(body.ResponseMarkers, s)
			}
		}
	}
	if verification, ok := parsed["verification"].(map[string]interface{}); ok {
		if delta, ok := verification["semantic_delta"].(map[string]interface{}); ok {
			body.SemanticDelta = delta
		}
		if proof, ok := verification["boolean_pair_proof"].(map[string]interface{}); ok {
			get := func(key string) string {
				value, _ := proof[key].(string)
				return value
			}
			orientation := "false branch matches baseline"
			if n, ok := proof["orientation"].(float64); ok && int(n) == 1 {
				orientation = "true branch matches baseline"
			}
			body.ProofSummary = fmt.Sprintf(
				"Boolean differential: %s; baseline/control=%s; true=%s; false=%s; second pair matched the same branch hashes",
				orientation, shortEvidenceHash(get("baseline_hash")), shortEvidenceHash(get("first_true_hash")),
				shortEvidenceHash(get("first_false_hash")),
			)
		}
	}
	if req, ok := parsed["request"].(map[string]interface{}); ok {
		body.Method, _ = req["method"].(string)
		body.URL, _ = req["url"].(string)
		reqHeaders := headerLines(req["headers"])
		reqBody, _ := req["body"].(string)
		if body.ReqHeaders == "" {
			body.ReqHeaders = reqHeaders
		}
		if body.ReqBody == "" {
			body.ReqBody = reqBody
		}
		body.RawRequest = buildRawRequest(body.Method, body.URL, reqHeaders, reqBody)
	}
	if resp, ok := parsed["response"].(map[string]interface{}); ok {
		if code, ok := resp["status_code"].(float64); ok {
			body.StatusCode = int(code)
		}
		if dur, ok := resp["duration"].(float64); ok {
			body.DurationMs = int64(dur / 1e6) // duration is stored in nanoseconds
		}
		respHeaders := headerLines(resp["headers"])
		respBody, _ := resp["body"].(string)
		if body.RespHeaders == "" {
			body.RespHeaders = respHeaders
		}
		if body.RespBody == "" {
			body.RespBody = respBody
		}
		body.RawResponse = buildRawResponse(body.StatusCode, respHeaders, respBody)
	}
	body.CurlCommand = buildCurlCommand(body.Method, body.URL, body.ReqHeaders, body.ReqBody)
	applyTypedEvidenceFallback(raw, &body)
	return body
}

func shortEvidenceHash(value string) string {
	if len(value) > 12 {
		return value[:12]
	}
	return value
}

// ParseEvidenceBody builds a structured HTTP evidence view from stored JSON.
func ParseEvidenceBody(raw string) EvidenceBody {
	return parseEvidenceBody(raw)
}

type moduleEvidenceJSON struct {
	Module  string `json:"module"`
	Signal  string `json:"signal"`
	OASTURL string `json:"oast_url"`
	Payload struct {
		Value string `json:"value"`
	} `json:"payload"`
	Request struct {
		Method  string            `json:"method"`
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	} `json:"request"`
	Response struct {
		StatusCode int               `json:"status_code"`
		Headers    map[string]string `json:"headers"`
		Body       string            `json:"body"`
		Duration   int64             `json:"duration"`
	} `json:"response"`
	Verification struct {
		Score            float64                       `json:"score"`
		ProofType        string                        `json:"proof_type"`
		ProofPolicy      string                        `json:"proof_policy_version"`
		ProofSatisfied   bool                          `json:"proof_satisfied"`
		DowngradeReasons []string                      `json:"downgrade_reasons"`
		UpgradeReasons   []string                      `json:"upgrade_reasons"`
		SemanticDelta    map[string]interface{}        `json:"semantic_delta"`
		Observations     []VerificationObservationView `json:"observations"`
	} `json:"verification"`
}

func applyTypedEvidenceFallback(raw string, body *EvidenceBody) {
	var ev moduleEvidenceJSON
	if json.Unmarshal([]byte(raw), &ev) != nil {
		return
	}
	body.ConfidenceScore = ev.Verification.Score
	body.ProofType = ev.Verification.ProofType
	body.ProofPolicy = ev.Verification.ProofPolicy
	body.ProofSatisfied = ev.Verification.ProofSatisfied
	body.DowngradeReasons = ev.Verification.DowngradeReasons
	body.UpgradeReasons = ev.Verification.UpgradeReasons
	body.SemanticDelta = ev.Verification.SemanticDelta
	body.Observations = ev.Verification.Observations
	if body.RawRequest != "" && body.RawResponse != "" {
		return
	}
	if body.Module == "" {
		body.Module = ev.Module
	}
	if body.Signal == "" {
		body.Signal = ev.Signal
	}
	if body.OASTURL == "" {
		body.OASTURL = ev.OASTURL
	}
	if body.Payload == "" {
		body.Payload = ev.Payload.Value
	}
	if body.Method == "" {
		body.Method = ev.Request.Method
	}
	if body.URL == "" {
		body.URL = ev.Request.URL
	}
	if body.ReqHeaders == "" && len(ev.Request.Headers) > 0 {
		body.ReqHeaders = headerLinesFromStringMap(ev.Request.Headers)
	}
	if body.ReqBody == "" {
		body.ReqBody = ev.Request.Body
	}
	if body.StatusCode == 0 {
		body.StatusCode = ev.Response.StatusCode
	}
	if body.DurationMs == 0 && ev.Response.Duration > 0 {
		if ev.Response.Duration > 1_000_000 {
			body.DurationMs = ev.Response.Duration / 1_000_000
		} else {
			body.DurationMs = ev.Response.Duration
		}
	}
	if body.RespHeaders == "" && len(ev.Response.Headers) > 0 {
		body.RespHeaders = headerLinesFromStringMap(ev.Response.Headers)
	}
	if body.RespBody == "" {
		body.RespBody = ev.Response.Body
	}
	if body.RawRequest == "" {
		body.RawRequest = buildRawRequest(body.Method, body.URL, body.ReqHeaders, body.ReqBody)
	}
	if body.RawResponse == "" {
		body.RawResponse = buildRawResponse(body.StatusCode, body.RespHeaders, body.RespBody)
	}
	if body.CurlCommand == "" {
		body.CurlCommand = buildCurlCommand(body.Method, body.URL, body.ReqHeaders, body.ReqBody)
	}
}

func headerLinesFromStringMap(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(m[k])
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n")
}

// headerLines renders a JSON headers map (map[string]interface{}) into sorted
// "Key: value" lines for display.
func headerLines(v interface{}) string {
	m, ok := v.(map[string]interface{})
	if !ok || len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		if s, ok := m[k].(string); ok {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(s)
			b.WriteByte('\n')
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func buildRawRequest(method, rawURL, headers, reqBody string) string {
	if method == "" && rawURL == "" {
		return ""
	}
	path := rawURL
	host := ""
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		host = u.Host
		path = u.RequestURI()
	}
	var b strings.Builder
	if method == "" {
		method = "GET"
	}
	b.WriteString(method)
	b.WriteByte(' ')
	b.WriteString(path)
	b.WriteString(" HTTP/1.1\n")
	if host != "" {
		b.WriteString("Host: ")
		b.WriteString(host)
		b.WriteByte('\n')
	}
	if headers != "" {
		b.WriteString(headers)
		b.WriteByte('\n')
	}
	if reqBody != "" {
		b.WriteByte('\n')
		b.WriteString(reqBody)
	}
	return strings.TrimRight(b.String(), "\n")
}

func buildCurlCommand(method, rawURL, headers, reqBody string) string {
	if strings.TrimSpace(rawURL) == "" {
		return ""
	}
	if method == "" {
		method = "GET"
	}
	var b strings.Builder
	b.WriteString("curl -i -X ")
	b.WriteString(method)
	b.WriteString(" ")
	b.WriteString(shellQuote(rawURL))
	for _, line := range strings.Split(headers, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if i := strings.Index(line, ":"); i > 0 {
			k := strings.TrimSpace(line[:i])
			v := strings.TrimSpace(line[i+1:])
			if strings.EqualFold(k, "Host") {
				continue
			}
			b.WriteString(" \\\n  -H ")
			b.WriteString(shellQuote(k + ": " + v))
		}
	}
	if reqBody != "" {
		b.WriteString(" \\\n  --data-raw ")
		b.WriteString(shellQuote(reqBody))
	}
	return b.String()
}

func shellQuote(s string) string {
	if s == "" {
		return `''`
	}
	if !strings.ContainsAny(s, " \t\n'\"\\$`") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func buildRawResponse(status int, headers, respBody string) string {
	if status == 0 && headers == "" && respBody == "" {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d\n", status)
	if headers != "" {
		b.WriteString(headers)
		b.WriteByte('\n')
	}
	if respBody != "" {
		b.WriteByte('\n')
		b.WriteString(respBody)
	}
	return strings.TrimRight(b.String(), "\n")
}

func RawHTTPFromRecord(rec RequestResponseRecord) (string, string) {
	var reqHeaders map[string]string
	var respHeaders map[string]string
	_ = json.Unmarshal([]byte(rec.ReqHeaders), &reqHeaders)
	_ = json.Unmarshal([]byte(rec.RespHeaders), &respHeaders)
	return buildRawRequest(rec.Method, rec.URL, headerLinesFromStringMap(reqHeaders), rec.ReqBody),
		buildRawResponse(rec.StatusCode, headerLinesFromStringMap(respHeaders), rec.RespBody)
}

func (db *DB) LoadRequestResponseLazy(requestID int64) (RequestResponseRecord, error) {
	recs, err := db.ListRequestResponses("", 1)
	_ = recs
	row := db.conn.QueryRow(`
SELECT r.id, r.method, r.url, COALESCE(r.headers_json,''), COALESCE(r.body,''),
       COALESCE(resp.status_code,0), COALESCE(resp.headers_json,''), COALESCE(resp.body,''),
       COALESCE(resp.duration_ms,0), r.created_at
FROM request_records r
LEFT JOIN response_records resp ON resp.request_id = r.id
WHERE r.id = ?`, requestID)
	var rec RequestResponseRecord
	err = row.Scan(&rec.RequestID, &rec.Method, &rec.URL, &rec.ReqHeaders, &rec.ReqBody,
		&rec.StatusCode, &rec.RespHeaders, &rec.RespBody, &rec.DurationMs, &rec.CreatedAt)
	return rec, err
}

func (db *DB) FuzzDashboardUI(scanID string) (FuzzDashboard, error) {
	d := FuzzDashboard{ByCategory: map[string]int{}, ByStatusCode: map[string]int{}}
	_ = db.conn.QueryRow(`SELECT COUNT(*) FROM fuzz_results WHERE scan_id = ?`, scanID).Scan(&d.Total)
	rows, err := db.conn.Query(`SELECT category, COUNT(*) FROM fuzz_results WHERE scan_id = ? GROUP BY category`, scanID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var cat string
			var n int
			if rows.Scan(&cat, &n) == nil {
				d.ByCategory[cat] = n
			}
		}
	}
	rows, err = db.conn.Query(`
SELECT status_code, COUNT(*) FROM fuzz_results WHERE scan_id = ? GROUP BY status_code`, scanID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var code int
			var n int
			if rows.Scan(&code, &n) == nil {
				key := fmt.Sprintf("%d", code)
				if code >= 500 {
					key = "50x"
				} else if code == 403 {
					key = "403"
				} else if code == 404 {
					key = "404"
				} else if code == 401 {
					key = "401"
				} else if code >= 300 && code < 400 {
					key = "30x"
				} else if code == 200 {
					key = "200"
				}
				d.ByStatusCode[key] += n
			}
		}
	}
	d.Notable, _ = db.ListFuzzResultRecords(scanID, 10)
	return d, nil
}

func (db *DB) ListBypass403UI(scanID string, limit int) ([]Bypass403Row, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := db.conn.Query(`
SELECT result_json FROM waf_bypass_results WHERE scan_id = ? ORDER BY id DESC LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byURL := map[string]*Bypass403Row{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var parsed struct {
			URL       string `json:"url"`
			Strategy  string `json:"strategy_id"`
			Succeeded bool   `json:"succeeded"`
		}
		_ = json.Unmarshal([]byte(raw), &parsed)
		if parsed.URL == "" {
			continue
		}
		row, ok := byURL[parsed.URL]
		if !ok {
			row = &Bypass403Row{URL: parsed.URL}
			byURL[parsed.URL] = row
		}
		row.AttemptCount++
		if parsed.Succeeded {
			row.SuccessCount++
			row.EvidenceJSON = raw
		}
		if parsed.Strategy != "" {
			row.Techniques = append(row.Techniques, parsed.Strategy)
		}
	}
	out := make([]Bypass403Row, 0, len(byURL))
	for _, v := range byURL {
		out = append(out, *v)
	}
	return out, nil
}

func (db *DB) TargetMapUI(scanID string) ([]TargetMapNode, error) {
	nodes := []TargetMapNode{{ID: "root", Label: "target", Type: "domain", Risk: "low", Count: 0}}
	rows, err := db.conn.Query(`
SELECT url, COUNT(*) FROM endpoints WHERE scan_id = ? GROUP BY url LIMIT 100`, scanID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var url string
			var n int
			if rows.Scan(&url, &n) != nil {
				continue
			}
			risk := "low"
			if n > 5 {
				risk = "medium"
			}
			nodes = append(nodes, TargetMapNode{
				ID: "ep-" + url, Label: trimURL(url), Type: "endpoint", Risk: risk, Count: n, ParentID: "root",
			})
		}
	}
	return nodes, nil
}

func (db *DB) ListTimelineUI(scanID string, eventType string, limit int) ([]TimelineRow, error) {
	if limit <= 0 {
		limit = 200
	}
	q := `SELECT id, event_type, summary, COALESCE(event_json,''), created_at FROM timeline_events WHERE scan_id = ?`
	args := []interface{}{scanID}
	if eventType != "" {
		q += ` AND event_type = ?`
		args = append(args, eventType)
	}
	q += ` ORDER BY id ASC LIMIT ?`
	args = append(args, limit)
	rows, err := db.conn.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TimelineRow
	for rows.Next() {
		var row TimelineRow
		if err := rows.Scan(&row.ID, &row.EventType, &row.Summary, &row.EventJSON, &row.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (db *DB) SaveAnnotation(findingID int64, annotationType, notes, annotatedBy string) error {
	_, err := db.conn.Exec(`
INSERT INTO user_finding_annotations (finding_id, annotation_type, notes, annotated_by) VALUES (?, ?, ?, ?)`,
		findingID, annotationType, notes, annotatedBy)
	return err
}

func (db *DB) ListAnnotations(findingID int64) ([]AnnotationRow, error) {
	rows, err := db.conn.Query(`
SELECT id, finding_id, annotation_type, COALESCE(notes,''), COALESCE(annotated_by,''), created_at
FROM user_finding_annotations WHERE finding_id = ? ORDER BY id DESC`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AnnotationRow
	for rows.Next() {
		var row AnnotationRow
		if err := rows.Scan(&row.ID, &row.FindingID, &row.AnnotationType, &row.Notes, &row.AnnotatedBy, &row.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (db *DB) LatestAnnotation(findingID int64) (AnnotationRow, error) {
	var row AnnotationRow
	err := db.conn.QueryRow(`
SELECT id, finding_id, annotation_type, COALESCE(notes,''), COALESCE(annotated_by,''), created_at
FROM user_finding_annotations WHERE finding_id = ? ORDER BY id DESC LIMIT 1`, findingID).Scan(
		&row.ID, &row.FindingID, &row.AnnotationType, &row.Notes, &row.AnnotatedBy, &row.CreatedAt)
	if err == sql.ErrNoRows {
		return row, nil
	}
	return row, err
}

func (db *DB) ListFindingGroupsUI(scanID string) ([]FindingGroupRecord, error) {
	return db.ListFindingGroups(scanID, 100)
}

func defaultImpactText(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "Critical business impact — potential full compromise."
	case "high":
		return "High impact to confidentiality, integrity, or availability."
	case "medium":
		return "Moderate security impact with limited blast radius."
	case "low":
		return "Low impact — defense in depth improvement recommended."
	default:
		return "Impact requires contextual review."
	}
}

func defaultRemediationText(vulnClass string) string {
	switch strings.ToLower(vulnClass) {
	case "xss":
		return "Encode output per context, enforce CSP, validate input."
	case "sqli":
		return "Use parameterized queries; eliminate string concatenation."
	case "ssrf":
		return "Restrict egress, validate URLs, block metadata endpoints."
	default:
		return "Apply secure coding guidance for the vulnerability class."
	}
}

func confidenceExplainText(label string) string {
	switch label {
	case "Confirmed":
		return "Deterministic verification succeeded."
	case "HighConfidence":
		return "Multiple corroborating signals; manual validation advised."
	case "Potential":
		return "Heuristic match — confirm manually before reporting."
	default:
		return "Needs manual validation."
	}
}

func trimURL(url string) string {
	if len(url) > 48 {
		return url[:45] + "…"
	}
	return url
}
