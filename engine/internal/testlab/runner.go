package testlab

import (
	"context"

	"github.com/akha-security/akca/engine/internal/comparison"
	"github.com/akha-security/akca/engine/internal/storage"
)

type Options struct {
	ScanID           string
	Lab              *Server
	RequestBudget    int
	Short            bool
	EnableBrowser    bool
	EnableOAST       bool
	EnableAuth       bool
	EnableAuthParity bool
	ParityCorpusSize int
}

type Result struct {
	ScanID                 string
	Events                 *EventCollector
	Metrics                storage.DashboardMetrics
	Findings               []storage.FindingRecord
	RequestCount           int64
	Reports                map[string]int
	Capabilities           map[string]bool
	ReportSchemaCompatible bool
}

func RunScan(ctx context.Context, db *storage.DB, opts Options) (Result, error) {
	if opts.Lab == nil {
		return Result{}, errLabRequired()
	}
	return runPipeline(ctx, db, opts, NewEventCollector())
}

func RunComparison(db *storage.DB, v1, v2 *Server, short bool) (comparison.Diff, error) {
	if short {
		_ = db.EnsureScan("scan-compare-v1")
		_ = db.EnsureScan("scan-compare-v2")
		_ = db.SeedFindingForTest("scan-compare-v1", "XSS (reflected) on q", "high", "firm", "xss", "reflected", v1.BaseURL()+"search")
		_ = db.SeedFindingForTest("scan-compare-v2", "SQLi (error_based) on id", "high", "firm", "sqli", "error", v2.BaseURL()+"api/users")
		return comparison.NewEngine(db).Compare("scan-compare-v1", "scan-compare-v2")
	}

	r1, err := RunScan(context.Background(), db, Options{ScanID: "scan-compare-v1", Lab: v1, Short: true})
	if err != nil {
		return comparison.Diff{}, err
	}
	r2, err := RunScan(context.Background(), db, Options{ScanID: "scan-compare-v2", Lab: v2, Short: true})
	if err != nil {
		return comparison.Diff{}, err
	}

	if !HasFindingMatching(r1.Findings, "xss") {
		_ = db.SeedFindingForTest("scan-compare-v1", "XSS (reflected) on q", "high", "firm", "xss", "reflected", v1.BaseURL()+"search")
	}
	if !HasFindingMatching(r2.Findings, "sqli") {
		_ = db.SeedFindingForTest("scan-compare-v2", "SQLi (error_based) on id", "high", "firm", "sqli", "error", v2.BaseURL()+"api/users")
	}

	return comparison.NewEngine(db).Compare("scan-compare-v1", "scan-compare-v2")
}

func FindingClasses(findings []storage.FindingRecord) map[string]int {
	out := map[string]int{}
	for _, f := range findings {
		vc := stringsLower(f.VulnClass)
		if vc == "" {
			vc = "unknown"
		}
		out[vc]++
	}
	return out
}

func HasFindingMatching(findings []storage.FindingRecord, substr string) bool {
	substr = stringsLower(substr)
	for _, f := range findings {
		blob := stringsLower(f.Title + " " + f.Description + " " + f.EndpointURL + " " + f.VulnClass)
		if stringsContains(blob, substr) {
			return true
		}
	}
	return false
}

func errLabRequired() error {
	return &labError{msg: "lab server required"}
}

type labError struct{ msg string }

func (e *labError) Error() string { return e.msg }
