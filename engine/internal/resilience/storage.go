package resilience

import (
	"fmt"

	"github.com/akha-security/akca/engine/internal/storage"
)

func SeedEndpoints(db *storage.DB, scanID string, urls []string) error {
	if err := db.EnsureScan(scanID); err != nil {
		return err
	}
	tx, err := db.Conn().Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO endpoints (scan_id, url, method, normalized_url) VALUES (?, ?, 'GET', ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, u := range urls {
		if _, err := stmt.Exec(scanID, u, u); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func SeedFuzzResults(db *storage.DB, scanID string, n int) error {
	if err := db.EnsureScan(scanID); err != nil {
		return err
	}
	tx, err := db.Conn().Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO fuzz_results (scan_id, url, method, status_code, category, result_json) VALUES (?, ?, 'GET', ?, 'fixture', ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for i := 0; i < n; i++ {
		url := fmt.Sprintf("https://fuzz.massive.test/%d", i)
		status := 200
		if i%17 == 0 {
			status = 403
		}
		if _, err := stmt.Exec(scanID, url, status, fmt.Sprintf(`{"i":%d}`, i)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func SeedFindings(db *storage.DB, scanID string, n int) error {
	if err := db.EnsureScan(scanID); err != nil {
		return err
	}
	tx, err := db.Conn().Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`
INSERT INTO findings (scan_id, title, description, severity, confidence, vuln_class, endpoint_url)
VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for i := 0; i < n; i++ {
		sev := "low"
		if i%5 == 0 {
			sev = "high"
		}
		vc := "xss"
		if i%3 == 0 {
			vc = "sqli"
		}
		title := fmt.Sprintf("Finding %d", i)
		ep := fmt.Sprintf("https://api.massive.test/v1/resource/%d", i)
		if _, err := stmt.Exec(scanID, title, "fixture", sev, "Potential", vc, ep); err != nil {
			return err
		}
	}
	return tx.Commit()
}
