package storage

import (
	"encoding/json"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

func (db *DB) SaveRequestResponse(scanID string, endpointID *int64, rr httpclient.RequestResponse) (int64, error) {
	reqHeaders, err := json.Marshal(rr.Request.Headers)
	if err != nil {
		return 0, err
	}
	res, err := db.conn.Exec(`
INSERT INTO request_records (scan_id, endpoint_id, method, url, headers_json, body)
VALUES (?, ?, ?, ?, ?, ?)`, scanID, endpointID, rr.Request.Method, rr.Request.URL, string(reqHeaders), rr.Request.Body)
	if err != nil {
		return 0, err
	}
	requestID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	respHeaders, err := json.Marshal(rr.Response.Headers)
	if err != nil {
		return 0, err
	}
	_, err = db.conn.Exec(`
INSERT INTO response_records (request_id, status_code, headers_json, body, duration_ms)
VALUES (?, ?, ?, ?, ?)`, requestID, rr.Response.StatusCode, string(respHeaders), rr.Response.Body, rr.Response.Duration.Milliseconds())
	return requestID, err
}
