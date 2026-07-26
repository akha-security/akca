package storage

import (
	"encoding/json"
	"strings"
)

func (db *DB) SaveCVECatalogEntry(cveID, catalogJSON, snapshotVersion string) error {
	_, err := db.conn.Exec(
		`INSERT INTO cve_catalog (cve_id, catalog_json, snapshot_version) VALUES (?, ?, ?)`,
		cveID, catalogJSON, snapshotVersion,
	)
	return err
}

func (db *DB) SaveComponent(scanID, componentJSON string) (int64, error) {
	res, err := db.conn.Exec(
		`INSERT INTO component_inventory (scan_id, component_json) VALUES (?, ?)`,
		scanID, componentJSON,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (db *DB) SaveComponentCVEMatch(componentID int64, cveID, matchJSON string) error {
	_, err := db.conn.Exec(
		`INSERT INTO component_cve_matches (component_id, cve_id, match_json) VALUES (?, ?, ?)`,
		componentID, cveID, matchJSON,
	)
	return err
}

type ScanComponentRecord struct {
	Vendor  string
	Product string
	Version string
	Source  string
}

// ListScanComponentsWithCVEs returns detected components and associated CVE IDs for recon.
func (db *DB) ListScanComponentsWithCVEs(scanID string) ([]ScanComponentRecord, map[string][]string, error) {
	rows, err := db.conn.Query(`
SELECT ci.component_json, COALESCE(GROUP_CONCAT(cc.cve_id), '')
FROM component_inventory ci
LEFT JOIN component_cve_matches cc ON cc.component_id = ci.id
WHERE ci.scan_id = ?
GROUP BY ci.id`, scanID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var comps []ScanComponentRecord
	cveMap := map[string][]string{}
	for rows.Next() {
		var raw, cveList string
		if err := rows.Scan(&raw, &cveList); err != nil {
			return nil, nil, err
		}
		var doc struct {
			Vendor  string `json:"vendor"`
			Product string `json:"product"`
			Version string `json:"version"`
			Source  string `json:"source"`
		}
		if json.Unmarshal([]byte(raw), &doc) != nil {
			continue
		}
		if doc.Product == "" {
			continue
		}
		rec := ScanComponentRecord{Vendor: doc.Vendor, Product: doc.Product, Version: doc.Version, Source: doc.Source}
		comps = append(comps, rec)
		key := strings.ToLower(doc.Product + "|" + doc.Version)
		if cveList != "" {
			for _, id := range strings.Split(cveList, ",") {
				id = strings.TrimSpace(id)
				if id != "" {
					cveMap[key] = append(cveMap[key], id)
				}
			}
		}
	}
	return comps, cveMap, rows.Err()
}

func (db *DB) ListCVECatalog() ([]string, error) {
	rows, err := db.conn.Query(`SELECT catalog_json FROM cve_catalog ORDER BY id DESC LIMIT 200`)
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

func (db *DB) SeedCVECatalogIfEmpty(entries []map[string]interface{}, snapshotVersion string) error {
	var count int
	if err := db.conn.QueryRow(`SELECT COUNT(1) FROM cve_catalog`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	for _, e := range entries {
		raw, _ := json.Marshal(e)
		cveID, _ := e["cve_id"].(string)
		if cveID == "" {
			continue
		}
		if err := db.SaveCVECatalogEntry(cveID, string(raw), snapshotVersion); err != nil {
			return err
		}
	}
	return nil
}
