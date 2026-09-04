package checkpoint

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/storage"
)

type FindingSummary struct {
	ID        int64  `json:"id"`
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	VulnClass string `json:"vuln_class"`
	Endpoint  string `json:"endpoint"`
	Parameter string `json:"parameter,omitempty"`
}

type DeltaReport struct {
	BaseScanID       string           `json:"base_scan_id"`
	CurrentScanID    string           `json:"current_scan_id"`
	GeneratedAt      time.Time        `json:"generated_at"`
	NewFindings      []FindingSummary `json:"new_findings"`
	ResolvedFindings []FindingSummary `json:"resolved_findings"`
	StableFindings   []FindingSummary `json:"stable_findings"`
	NewEndpoints     []string         `json:"new_endpoints"`
	TotalNew         int              `json:"total_new"`
	TotalResolved    int              `json:"total_resolved"`
	TotalStable      int              `json:"total_stable"`
}

// ComputeDelta compares findings and endpoints between two scans.
func ComputeDelta(db *storage.DB, baseScanID, currentScanID string) (*DeltaReport, error) {
	if db == nil {
		return nil, fmt.Errorf("database handle is nil")
	}

	baseRecords, err := db.ListFindings(baseScanID, 10000, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch base findings: %w", err)
	}

	currRecords, err := db.ListFindings(currentScanID, 10000, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch current findings: %w", err)
	}

	baseMap := make(map[string]storage.FindingRecord)
	for _, f := range baseRecords {
		key := findingFingerprint(f.VulnClass, f.EndpointURL, f.Parameter)
		baseMap[key] = f
	}

	currMap := make(map[string]storage.FindingRecord)
	for _, f := range currRecords {
		key := findingFingerprint(f.VulnClass, f.EndpointURL, f.Parameter)
		currMap[key] = f
	}

	report := &DeltaReport{
		BaseScanID:    baseScanID,
		CurrentScanID: currentScanID,
		GeneratedAt:   time.Now().UTC(),
	}

	// 1. Identify New and Stable findings
	for key, curr := range currMap {
		summary := FindingSummary{
			ID:        curr.ID,
			Title:     curr.Title,
			Severity:  curr.Severity,
			VulnClass: curr.VulnClass,
			Endpoint:  curr.EndpointURL,
			Parameter: curr.Parameter,
		}
		if _, exists := baseMap[key]; exists {
			report.StableFindings = append(report.StableFindings, summary)
		} else {
			report.NewFindings = append(report.NewFindings, summary)
		}
	}

	// 2. Identify Resolved findings
	for key, base := range baseMap {
		if _, exists := currMap[key]; !exists {
			report.ResolvedFindings = append(report.ResolvedFindings, FindingSummary{
				ID:        base.ID,
				Title:     base.Title,
				Severity:  base.Severity,
				VulnClass: base.VulnClass,
				Endpoint:  base.EndpointURL,
				Parameter: base.Parameter,
			})
		}
	}

	report.TotalNew = len(report.NewFindings)
	report.TotalResolved = len(report.ResolvedFindings)
	report.TotalStable = len(report.StableFindings)

	return report, nil
}

func findingFingerprint(vulnClass, endpoint, parameter string) string {
	h := sha256.New()
	h.Write([]byte(strings.ToLower(strings.TrimSpace(vulnClass))))
	h.Write([]byte{0})
	h.Write([]byte(strings.ToLower(strings.TrimSpace(endpoint))))
	h.Write([]byte{0})
	h.Write([]byte(strings.ToLower(strings.TrimSpace(parameter))))
	return fmt.Sprintf("%x", h.Sum(nil))
}
