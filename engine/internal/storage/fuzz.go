package storage

import (
	"encoding/json"
	"fmt"
	"strings"
)

func (db *DB) SaveFuzzResult(scanID string, result interface{}) error {
	b, err := json.Marshal(result)
	if err != nil {
		return err
	}
	type fields struct {
		URL        string `json:"url"`
		Method     string `json:"method"`
		StatusCode int    `json:"status_code"`
		Category   string `json:"category"`
		Signal     string `json:"signal"`
	}
	var f fields
	_ = json.Unmarshal(b, &f)
	_, err = db.conn.Exec(`
INSERT INTO fuzz_results (scan_id, url, method, status_code, category, result_json)
VALUES (?, ?, ?, ?, ?, ?)`,
		scanID, f.URL, f.Method, f.StatusCode, f.Category, string(b),
	)
	return err
}

// Fuzz403Entry is a URL that returned HTTP 403 during fuzzing.
type Fuzz403Entry struct {
	URL    string
	Method string
}

// ListFuzz403URLs returns distinct URLs that received HTTP 403 during fuzzing.
func (db *DB) ListFuzz403URLs(scanID string, limit int) ([]Fuzz403Entry, error) {
	return db.listFuzzAuthBlockedURLs(scanID, limit, 403)
}

// ListFuzzAuthBlockedURLs returns distinct URLs that returned 401 or 403 during fuzzing.
func (db *DB) ListFuzzAuthBlockedURLs(scanID string, limit int) ([]Fuzz403Entry, error) {
	return db.listFuzzAuthBlockedURLs(scanID, limit, 401, 403)
}

func (db *DB) listFuzzAuthBlockedURLs(scanID string, limit int, codes ...int) ([]Fuzz403Entry, error) {
	if limit <= 0 {
		limit = 5000
	}
	if len(codes) == 0 {
		return nil, nil
	}
	placeholders := make([]string, len(codes))
	args := make([]interface{}, 0, len(codes)+2)
	args = append(args, scanID)
	for i, c := range codes {
		placeholders[i] = "?"
		args = append(args, c)
	}
	args = append(args, limit)
	query := fmt.Sprintf(`
SELECT DISTINCT url, method FROM fuzz_results
WHERE scan_id = ? AND status_code IN (%s)
ORDER BY id ASC LIMIT ?`, strings.Join(placeholders, ","))
	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Fuzz403Entry
	for rows.Next() {
		var e Fuzz403Entry
		if err := rows.Scan(&e.URL, &e.Method); err != nil {
			return nil, err
		}
		if e.Method == "" {
			e.Method = "GET"
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
