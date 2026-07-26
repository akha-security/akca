package app

import (
	"context"
	"encoding/json"
	"time"
)

func (e *Engine) ReplayRequest(params map[string]interface{}) (map[string]interface{}, error) {
	method := strParam(params, "method")
	if method == "" {
		method = "GET"
	}
	url := strParam(params, "url")
	body := strParam(params, "body")
	headers := map[string]string{}
	if raw, ok := params["headers"].(map[string]interface{}); ok {
		for k, v := range raw {
			headers[k] = toString(v)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rr, err := e.HTTPClient().Do(ctx, method, url, []byte(body), headers)
	if err != nil {
		return nil, err
	}
	reqJSON, _ := json.Marshal(rr.Request)
	respJSON, _ := json.Marshal(rr.Response)
	sess := e.currentSession()
	scanID := sess.ID
	if scanID == "" {
		scanID = sess.Config.ScanID
	}
	id, _ := e.db.SaveCommandCenterRequest(scanID, string(reqJSON), string(respJSON))
	return map[string]interface{}{
		"id":               id,
		"status_code":      rr.Response.StatusCode,
		"response_body":    truncateStr(rr.Response.Body, 8000),
		"response_headers": rr.Response.Headers,
		"duration_ms":      rr.Response.Duration.Milliseconds(),
		"request_json":     string(reqJSON),
		"response_json":    string(respJSON),
	}, nil
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func toString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
