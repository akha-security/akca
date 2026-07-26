package storage

import "fmt"

func (db *DB) SaveRuntimeTrace(traceID, scanID, requestID, candidateID, endpoint, parameter, verdict,
	traceJSON string) error {
	result, err := db.conn.Exec(`
INSERT INTO runtime_traces
  (trace_id, scan_id, request_id, candidate_id, endpoint_url, parameter, verdict, trace_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(trace_id) DO UPDATE SET
  verdict=excluded.verdict, trace_json=excluded.trace_json
WHERE runtime_traces.scan_id=excluded.scan_id
  AND runtime_traces.request_id=excluded.request_id
  AND runtime_traces.candidate_id=excluded.candidate_id
`, traceID, scanID, requestID, candidateID, endpoint, parameter, verdict, traceJSON)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return fmt.Errorf("runtime trace ID correlation conflict")
	}
	return nil
}

type RuntimeTraceRecord struct {
	TraceID     string `json:"trace_id"`
	ScanID      string `json:"scan_id"`
	RequestID   string `json:"request_id"`
	CandidateID string `json:"candidate_id"`
	Endpoint    string `json:"endpoint"`
	Parameter   string `json:"parameter,omitempty"`
	Verdict     string `json:"verdict"`
	TraceJSON   string `json:"trace_json"`
	CreatedAt   string `json:"created_at"`
}

func (db *DB) ListRuntimeTraces(scanID string, limit int) ([]RuntimeTraceRecord, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := db.conn.Query(`
SELECT trace_id, scan_id, request_id, candidate_id, endpoint_url, parameter, verdict, trace_json, created_at
FROM runtime_traces WHERE scan_id = ? ORDER BY created_at DESC LIMIT ?`, scanID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RuntimeTraceRecord
	for rows.Next() {
		var row RuntimeTraceRecord
		if err := rows.Scan(&row.TraceID, &row.ScanID, &row.RequestID, &row.CandidateID,
			&row.Endpoint, &row.Parameter, &row.Verdict, &row.TraceJSON, &row.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
