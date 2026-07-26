package storage

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"

	"github.com/akha-security/akca/engine/internal/models"
)

type ReconTechUI struct {
	Host            string                    `json:"host"`
	BackendLanguage string                    `json:"backend_language,omitempty"`
	Framework       string                    `json:"framework,omitempty"`
	Database        string                    `json:"database,omitempty"`
	ServerCDN       string                    `json:"server_cdn,omitempty"`
	JSFramework     string                    `json:"js_framework,omitempty"`
	Hints           []string                  `json:"hints,omitempty"`
	DetectedAt      string                    `json:"detected_at,omitempty"`
	HTTPStatus      int                       `json:"http_status,omitempty"`
	PageTitle       string                    `json:"page_title,omitempty"`
	MetaGenerator   string                    `json:"meta_generator,omitempty"`
	ContentType     string                    `json:"content_type,omitempty"`
	Components      []models.TechComponent    `json:"components,omitempty"`
	ResponseHeaders map[string]string         `json:"response_headers,omitempty"`
	SecurityHeaders models.ReconSecurityAudit `json:"security_headers,omitempty"`
	Cookies         []models.ReconCookie      `json:"cookies,omitempty"`
	TLSHints        []string                  `json:"tls_hints,omitempty"`
}

type ReconWAFUI struct {
	Host                    string   `json:"host"`
	Vendor                  string   `json:"vendor,omitempty"`
	CDN                     string   `json:"cdn,omitempty"`
	HeaderSignatures        []string `json:"header_signatures,omitempty"`
	BodySignatures          []string `json:"body_signatures,omitempty"`
	RateLimitDetected       bool     `json:"rate_limit_detected"`
	ChallengePageDetected   bool     `json:"challenge_page_detected"`
	CautiousModeRecommended bool     `json:"cautious_mode_recommended"`
	Confidence              float64  `json:"confidence"`
	DetectedAt              string   `json:"detected_at,omitempty"`
}

type ReconComponentUI struct {
	Name     string   `json:"name"`
	Version  string   `json:"version,omitempty"`
	Vendor   string   `json:"vendor,omitempty"`
	Product  string   `json:"product,omitempty"`
	Category string   `json:"category,omitempty"`
	Source   string   `json:"source,omitempty"`
	CVEIDs   []string `json:"cve_ids,omitempty"`
}

type ReconSurfaceStats struct {
	EndpointCount  int            `json:"endpoint_count"`
	FindingCount   int            `json:"finding_count"`
	Methods        map[string]int `json:"methods,omitempty"`
	Sources        map[string]int `json:"sources,omitempty"`
	ParameterCount int            `json:"parameter_count,omitempty"`
}

type ReconSnapshotUI struct {
	ScanID      string             `json:"scan_id"`
	PrimaryHost string             `json:"primary_host,omitempty"`
	PrimaryURL  string             `json:"primary_url,omitempty"`
	Tech        []ReconTechUI      `json:"tech"`
	WAF         []ReconWAFUI       `json:"waf"`
	Components  []ReconComponentUI `json:"components"`
	Surface     ReconSurfaceStats  `json:"surface"`
}

func (db *DB) GetReconUI(scanID string) (ReconSnapshotUI, error) {
	out := ReconSnapshotUI{ScanID: scanID}

	cfgJSON, _ := db.GetScanConfig(scanID)
	out.PrimaryURL = extractFirstTarget(cfgJSON)
	if out.PrimaryURL != "" {
		if u, err := url.Parse(out.PrimaryURL); err == nil && u.Host != "" {
			out.PrimaryHost = u.Host
		}
	}

	wafRecs, _ := db.ListWAFProfileRecords(scanID, 50)
	for _, rec := range wafRecs {
		var p ReconWAFUI
		if json.Unmarshal([]byte(rec.ProfileJSON), &p) == nil {
			if p.Host == "" {
				p.Host = rec.Host
			}
			if p.Vendor == "" {
				p.Vendor = rec.Vendor
			}
			out.WAF = append(out.WAF, p)
		} else {
			out.WAF = append(out.WAF, ReconWAFUI{Host: rec.Host, Vendor: rec.Vendor})
		}
	}

	techRecs, _ := db.ListTechFingerprintRecords(scanID, 50)
	compSeen := map[string]ReconComponentUI{}
	for _, rec := range techRecs {
		var t ReconTechUI
		if json.Unmarshal([]byte(rec.FingerprintJSON), &t) == nil {
			if t.Host == "" {
				t.Host = rec.Host
			}
			out.Tech = append(out.Tech, t)
			for _, c := range t.Components {
				mergeReconComponent(compSeen, ReconComponentUI{
					Name: c.Name, Version: c.Version, Category: c.Category, Source: c.Source,
					Product: c.Name, Vendor: c.Name,
				})
			}
		}
	}

	invComps, cveMap, _ := db.ListScanComponentsWithCVEs(scanID)
	for _, c := range invComps {
		key := strings.ToLower(c.Product + "|" + c.Version)
		existing := compSeen[key]
		existing.Name = c.Product
		existing.Product = c.Product
		existing.Vendor = c.Vendor
		existing.Version = c.Version
		existing.Source = c.Source
		if existing.Category == "" {
			existing.Category = "component"
		}
		if ids := cveMap[key]; len(ids) > 0 {
			existing.CVEIDs = ids
		}
		compSeen[key] = existing
	}
	out.Components = sortedComponents(compSeen)

	out.Surface = db.reconSurfaceStats(scanID)

	if out.PrimaryHost == "" {
		if len(out.Tech) > 0 && out.Tech[0].Host != "" {
			out.PrimaryHost = out.Tech[0].Host
		} else if len(out.WAF) > 0 && out.WAF[0].Host != "" {
			out.PrimaryHost = out.WAF[0].Host
		}
	}
	return out, nil
}

func mergeReconComponent(seen map[string]ReconComponentUI, c ReconComponentUI) {
	key := strings.ToLower(c.Name + "|" + c.Version)
	if prev, ok := seen[key]; ok {
		if c.Version != "" && prev.Version == "" {
			prev.Version = c.Version
		}
		if c.Source != "" && prev.Source == "" {
			prev.Source = c.Source
		}
		seen[key] = prev
		return
	}
	if c.Product == "" {
		c.Product = c.Name
	}
	if c.Vendor == "" {
		c.Vendor = c.Name
	}
	seen[key] = c
}

func sortedComponents(seen map[string]ReconComponentUI) []ReconComponentUI {
	out := make([]ReconComponentUI, 0, len(seen))
	for _, c := range seen {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func (db *DB) reconSurfaceStats(scanID string) ReconSurfaceStats {
	stats := ReconSurfaceStats{Methods: map[string]int{}, Sources: map[string]int{}}
	_ = db.conn.QueryRow(`SELECT COUNT(*) FROM endpoints WHERE scan_id = ?`, scanID).Scan(&stats.EndpointCount)
	_ = db.conn.QueryRow(`SELECT COUNT(*) FROM findings WHERE scan_id = ?`, scanID).Scan(&stats.FindingCount)
	_ = db.conn.QueryRow(`
SELECT COUNT(DISTINCT p.name) FROM parameters p
JOIN endpoints e ON e.id = p.endpoint_id WHERE e.scan_id = ?`, scanID).Scan(&stats.ParameterCount)

	rows, err := db.conn.Query(`SELECT method, COUNT(*) FROM endpoints WHERE scan_id = ? GROUP BY method`, scanID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var m string
			var n int
			if rows.Scan(&m, &n) == nil {
				if m == "" {
					m = "GET"
				}
				stats.Methods[strings.ToUpper(m)] = n
			}
		}
	}
	rows2, err := db.conn.Query(`SELECT COALESCE(discovery_source,''), COUNT(*) FROM endpoints WHERE scan_id = ? GROUP BY discovery_source`, scanID)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var src string
			var n int
			if rows2.Scan(&src, &n) == nil {
				if src == "" {
					src = "unknown"
				}
				stats.Sources[src] = n
			}
		}
	}
	return stats
}

func extractFirstTarget(cfgJSON string) string {
	if cfgJSON == "" || cfgJSON == "{}" {
		return ""
	}
	var doc struct {
		Targets []string `json:"targets"`
	}
	if json.Unmarshal([]byte(cfgJSON), &doc) != nil {
		return ""
	}
	if len(doc.Targets) > 0 {
		return strings.TrimSpace(doc.Targets[0])
	}
	return ""
}
