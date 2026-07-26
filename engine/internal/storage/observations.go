package storage

import (
	"time"
)

type VerificationObservationRecord struct {
	ID              string    `json:"id"`
	FindingID       int64     `json:"finding_id,omitempty"`
	ScanID          string    `json:"scan_id"`
	Module          string    `json:"module"`
	Endpoint        string    `json:"endpoint"`
	Parameter       string    `json:"parameter,omitempty"`
	Location        string    `json:"location,omitempty"`
	Role            string    `json:"role"`
	Attempt         int       `json:"attempt"`
	IdentityID      string    `json:"identity_id,omitempty"`
	RequestID       string    `json:"request_id,omitempty"`
	RequestMethod   string    `json:"request_method,omitempty"`
	RequestURL      string    `json:"request_url,omitempty"`
	RequestHash     string    `json:"request_hash,omitempty"`
	ResponseHash    string    `json:"response_hash,omitempty"`
	NormalizedHash  string    `json:"normalized_hash,omitempty"`
	StatusCode      int       `json:"status_code,omitempty"`
	ContentType     string    `json:"content_type,omitempty"`
	DurationMs      int64     `json:"duration_ms,omitempty"`
	StateBeforeHash string    `json:"state_before_hash,omitempty"`
	StateAfterHash  string    `json:"state_after_hash,omitempty"`
	OASTPayloadID   string    `json:"oast_payload_id,omitempty"`
	RuntimeTraceID  string    `json:"runtime_trace_id,omitempty"`
	RuntimeSink     string    `json:"runtime_sink,omitempty"`
	RuntimeSafe     bool      `json:"runtime_safe,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

func (db *DB) SaveVerificationObservation(findingID int64, item VerificationObservationRecord) error {
	var finding interface{}
	if findingID > 0 {
		finding = findingID
	}
	_, err := db.conn.Exec(`
INSERT OR IGNORE INTO verification_observations (
  id, finding_id, scan_id, module, endpoint_url, parameter, location, role, attempt,
  identity_id, request_id, request_method, request_url, request_hash, response_hash,
  normalized_hash, status_code, content_type, duration_ms, state_before_hash,
  state_after_hash, oast_payload_id, runtime_trace_id, runtime_sink, runtime_safe, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		item.ID, finding, item.ScanID, item.Module, item.Endpoint, item.Parameter, item.Location,
		item.Role, item.Attempt, item.IdentityID, item.RequestID, item.RequestMethod, item.RequestURL,
		item.RequestHash, item.ResponseHash, item.NormalizedHash, item.StatusCode, item.ContentType,
		item.DurationMs, item.StateBeforeHash, item.StateAfterHash, item.OASTPayloadID,
		item.RuntimeTraceID, item.RuntimeSink, item.RuntimeSafe,
		item.CreatedAt.UTC().Format(time.RFC3339Nano),
	)
	return err
}

func (db *DB) ListVerificationObservations(scanID string, findingID int64, limit int) ([]VerificationObservationRecord, error) {
	query := `
SELECT id, COALESCE(finding_id,0), scan_id, module, endpoint_url, COALESCE(parameter,''),
       COALESCE(location,''), role, attempt, COALESCE(identity_id,''), COALESCE(request_id,''),
       COALESCE(request_method,''), COALESCE(request_url,''), COALESCE(request_hash,''),
       COALESCE(response_hash,''), COALESCE(normalized_hash,''), COALESCE(status_code,0),
       COALESCE(content_type,''), COALESCE(duration_ms,0), COALESCE(state_before_hash,''),
       COALESCE(state_after_hash,''), COALESCE(oast_payload_id,''),
       COALESCE(runtime_trace_id,''), COALESCE(runtime_sink,''), COALESCE(runtime_safe,0), created_at
FROM verification_observations WHERE scan_id = ?`
	args := []interface{}{scanID}
	if findingID > 0 {
		query += ` AND finding_id = ?`
		args = append(args, findingID)
	}
	query += ` ORDER BY created_at, attempt, role`
	if limit <= 0 {
		limit = 1000
	}
	query += ` LIMIT ?`
	args = append(args, limit)
	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VerificationObservationRecord
	for rows.Next() {
		var item VerificationObservationRecord
		var created string
		if err := rows.Scan(
			&item.ID, &item.FindingID, &item.ScanID, &item.Module, &item.Endpoint, &item.Parameter,
			&item.Location, &item.Role, &item.Attempt, &item.IdentityID, &item.RequestID,
			&item.RequestMethod, &item.RequestURL, &item.RequestHash, &item.ResponseHash,
			&item.NormalizedHash, &item.StatusCode, &item.ContentType, &item.DurationMs,
			&item.StateBeforeHash, &item.StateAfterHash, &item.OASTPayloadID,
			&item.RuntimeTraceID, &item.RuntimeSink, &item.RuntimeSafe, &created,
		); err != nil {
			return nil, err
		}
		item.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		out = append(out, item)
	}
	return out, rows.Err()
}
