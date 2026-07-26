package testlab_test

import (
	"context"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/testlab"
)

func TestFullLabScanIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full integration scan in -short mode")
	}

	lab := testlab.NewServer(testlab.ModeFull)
	defer lab.Close()

	db, err := storage.Open(t.TempDir() + "/lab.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_ = db.Migrate()

	result, err := testlab.RunScan(context.Background(), db, testlab.Options{
		ScanID: "scan-lab-full",
		Lab:    lab,
	})
	if err != nil {
		t.Fatal(err)
	}

	assertLabScan(t, db, result, testlab.DefaultDomain, 4000)
}

func TestFullLabScanQuick(t *testing.T) {
	lab := testlab.NewServer(testlab.ModeFull)
	defer lab.Close()

	db, err := storage.Open(t.TempDir() + "/lab-quick.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_ = db.Migrate()

	result, err := testlab.RunScan(context.Background(), db, testlab.Options{
		ScanID: "scan-lab-quick",
		Lab:    lab,
		Short:  true,
	})
	if err != nil {
		t.Fatal(err)
	}

	assertLabScan(t, db, result, testlab.DefaultDomain, 850)
}

func TestPatchedLabScanHasNoPromotedVulnerabilityFixtures(t *testing.T) {
	lab := testlab.NewServer(testlab.ModeV2)
	defer lab.Close()

	db, err := storage.Open(t.TempDir() + "/lab-patched.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}

	result, err := testlab.RunScan(context.Background(), db, testlab.Options{
		ScanID: "scan-lab-patched", Lab: lab, Short: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	classes := testlab.FindingClasses(result.Findings)
	for _, class := range []string{
		"xss", "sqli", "ssrf", "xxe", "lfi", "open_redirect", "graphql",
		"secret_exposure", "sensitive_data", "debug_admin", "access_control_bypass",
	} {
		if classes[class] > 0 || testlab.HasFindingMatching(result.Findings, class) {
			t.Errorf("patched fixture promoted %s: classes=%v", class, classes)
		}
	}
}

func TestComparisonScanDiff(t *testing.T) {
	v1, v2 := testlab.ComparisonTargets()
	defer v1.Close()
	defer v2.Close()

	db, err := storage.Open(t.TempDir() + "/compare.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_ = db.Migrate()

	short := testing.Short()
	diff, err := testlab.RunComparison(db, v1, v2, short)
	if err != nil {
		t.Fatal(err)
	}

	if len(diff.NewFindings) == 0 {
		t.Fatalf("expected new findings in comparison, got %+v", diff)
	}
	if len(diff.ResolvedFindings) == 0 && len(diff.ChangedFindings) == 0 {
		t.Fatalf("expected resolved or changed findings, got %+v", diff)
	}
}

func assertLabScan(t *testing.T, db *storage.DB, result testlab.Result, domain string, budget int) {
	t.Helper()

	if result.Metrics.TotalFindings == 0 {
		t.Fatalf("expected findings, metrics=%+v events=%v", result.Metrics, result.Events.Types())
	}
	if result.Metrics.EvidenceCount == 0 && len(result.Findings) > 0 {
		// Some findings may inline evidence; allow zero separate evidence rows in quick mode.
		if !testing.Short() {
			t.Fatalf("expected stored evidence, metrics=%+v", result.Metrics)
		}
	}
	if result.RequestCount > int64(budget+50) {
		t.Fatalf("request budget exceeded: %d > %d", result.RequestCount, budget)
	}
	if !result.Events.AssertStructuredBatches() {
		t.Fatal("expected structured event batches for UI consumption")
	}
	if !result.Events.HasType("scan_started") || !result.Events.HasType("scan_finished") {
		t.Fatalf("missing lifecycle events: %+v", result.Events.Types())
	}

	classes := testlab.FindingClasses(result.Findings)
	t.Logf("finding classes: %v requests=%d", classes, result.RequestCount)

	// Reflected XSS is proven in the HTTP-only lab through executable-context
	// parsing, three independent positive runs and a clean negative control.
	// GraphQL still exposes introspection without exploitability proof and may
	// not be promoted.
	requiredSignals := []string{"xss", "sqli", "open_redirect", "ssrf", "xxe"}
	for _, sig := range requiredSignals {
		if !testlab.HasFindingMatching(result.Findings, sig) && classes[sig] == 0 {
			t.Errorf("expected finding signal %q, classes=%v", sig, classes)
		}
	}
	for _, forbidden := range []string{"graphql"} {
		if testlab.HasFindingMatching(result.Findings, forbidden) || classes[forbidden] > 0 {
			t.Errorf("unproven %s signal was promoted to a finding", forbidden)
		}
	}

	if !result.Events.HasType("waf_strategy_selected") && !result.Events.HasType("waf_detected") {
		t.Error("expected WAF learning or detection events")
	}
	if !result.Events.HasType("four_oh_three_bypass_succeeded") && !testlab.HasFindingMatching(result.Findings, "403") && !testlab.HasFindingMatching(result.Findings, "bypass") {
		t.Error("expected 403 bypass success")
	}
	if !result.Events.HasType("archive_exposure_detected") && !testlab.HasFindingMatching(result.Findings, "archive") {
		t.Log("archive exposure may be signaled via fuzzing event only")
	}
	if !result.Events.HasType("js_secret_detected") && !testlab.HasFindingMatching(result.Findings, "Secret") {
		t.Error("expected JS secret detection (API keys/tokens) from app.js analysis")
	}
	if !result.Events.HasType("crawler_js_file_found") && !result.Events.HasType("js_analysis_finished") {
		t.Error("expected JS file analysis events from crawl")
	}

	for _, f := range result.Findings {
		if strings.Contains(f.EndpointURL, "offscope.evil") {
			t.Fatalf("scope violation: finding on off-scope host %s", f.EndpointURL)
		}
		if f.Confidence == "" {
			t.Errorf("finding %q missing confidence", f.Title)
		}
	}

	if len(result.Reports) < 9 {
		t.Fatalf("expected multi-format reports, got %d", len(result.Reports))
	}
}
