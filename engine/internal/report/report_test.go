package report

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/evidencestore"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/testfixtures"
)

func TestVulnerabilityOverviewShowsCountsInDescendingOrder(t *testing.T) {
	html := vulnerabilityOverviewHTML(storage.DashboardMetrics{ByVulnClass: map[string]int{
		"sqli": 10, "ssrf": 5, "xss": 20,
	}})
	for _, want := range []string{"Cross-Site Scripting (XSS)", "SQL Injection", "Server-Side Request Forgery (SSRF)", `data-vclass="sqli"`} {
		if !strings.Contains(html, want) {
			t.Fatalf("vulnerability overview omitted %q: %s", want, html)
		}
	}
	xssIndex := strings.Index(html, "Cross-Site Scripting (XSS)")
	sqlIndex := strings.Index(html, "SQL Injection")
	ssrfIndex := strings.Index(html, "Server-Side Request Forgery (SSRF)")
	if !(xssIndex < sqlIndex && sqlIndex < ssrfIndex) {
		t.Fatalf("overview is not ordered by count: %s", html)
	}
}

func setupReportDB(t *testing.T, findingCount int) (*storage.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "akca.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	scanID := "scan-report-test"
	if err := db.EnsureScan(scanID); err != nil {
		t.Fatal(err)
	}
	severities := []string{"critical", "high", "medium", "low"}
	for i := 0; i < findingCount; i++ {
		sev := severities[i%len(severities)]
		desc := "Test finding with Bearer secret-token-abc123 for validation"
		evidence := `{"module":"xss","verification":{"proof_type":"content_evidence","proof_policy_version":"3.0","proof_satisfied":true}}`
		if _, err := db.SaveFinding(scanID, "Finding "+string(rune('A'+i%26)), sev, "xss", desc, "https://example.com/p", "", 0.95, evidence); err != nil {
			t.Fatal(err)
		}
	}
	_ = db.SaveAPIKeyValidation(scanID, "GitHub", "valid", map[string]string{"key": testfixtures.GitHubReportToken()})
	_ = db.SaveFindingGroup(scanID, "missing_output_encoding", map[string]int{"count": 3})
	return db, scanID
}

func TestExportFormatsSampleData(t *testing.T) {
	db, scanID := setupReportDB(t, 5)
	defer db.Close()

	store := evidencestore.New(db)
	builder := NewBuilder(store, db)
	var progressEvents []Progress
	exporter := NewExporter(builder, func(p Progress) { progressEvents = append(progressEvents, p) })

	opts := Options{ScanID: scanID, Template: TemplateHackerOne, Format: FormatHTML, Redact: true}
	var htmlBuf bytes.Buffer
	if err := exporter.Export(&htmlBuf, opts); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(htmlBuf.String(), ProductName) {
		t.Fatal("expected product title")
	}
	if strings.Contains(htmlBuf.String(), "[REDACTED]") {
		t.Fatal("did not expect redacted markers in HTML")
	}

	opts.Template = TemplateBugcrowd
	opts.Format = FormatJSON
	var jsonBuf bytes.Buffer
	if err := exporter.Export(&jsonBuf, opts); err != nil {
		t.Fatal(err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(jsonBuf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	findings, _ := parsed["findings"].([]interface{})
	if len(findings) != 5 {
		t.Fatalf("expected 5 findings, got %d", len(findings))
	}

	opts.Format = FormatCSV
	var csvBuf bytes.Buffer
	if err := exporter.Export(&csvBuf, opts); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(csvBuf.String()), "\n")
	if len(lines) < 6 {
		t.Fatalf("expected header + 5 rows, got %d lines", len(lines))
	}

	opts.Format = FormatMarkdown
	var mdBuf bytes.Buffer
	if err := exporter.Export(&mdBuf, opts); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(mdBuf.String(), "## Findings") {
		t.Fatal("expected markdown findings section")
	}

	if len(progressEvents) == 0 {
		t.Fatal("expected report_generation_progress callbacks")
	}

	opts.Format = FormatSARIF
	var sarifBuf bytes.Buffer
	if err := exporter.Export(&sarifBuf, opts); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sarifBuf.String(), `"version": "2.1.0"`) ||
		!strings.Contains(sarifBuf.String(), `"ruleId": "xss"`) ||
		!strings.Contains(sarifBuf.String(), ProductName) {
		t.Fatalf("invalid SARIF output: %s", sarifBuf.String())
	}
}

func TestPathDiscoverySectionUsesFuzzResults(t *testing.T) {
	db, scanID := setupReportDB(t, 0)
	defer db.Close()
	if err := db.SaveFuzzResult(scanID, map[string]interface{}{
		"url": "https://example.com/admin", "method": "GET", "status_code": 200,
		"category": "admin", "signal": "ok", "body_length": 123,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveFuzzResult(scanID, map[string]interface{}{
		"url": "https://example.com/missing", "method": "GET", "status_code": 404,
		"category": "general", "signal": "not_found",
	}); err != nil {
		t.Fatal(err)
	}

	builder := NewBuilder(evidencestore.New(db), db)
	meta, err := builder.BuildMeta(Options{ScanID: scanID, Template: TemplateInternal, Redact: false})
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.PathDiscoveries) != 1 || meta.PathDiscoveries[0].URL != "https://example.com/admin" {
		t.Fatalf("unexpected path discoveries: %+v", meta.PathDiscoveries)
	}
	var htmlBuf bytes.Buffer
	if err := NewExporter(builder, nil).Export(&htmlBuf, Options{ScanID: scanID, Template: TemplateInternal, Format: FormatHTML}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(htmlBuf.String(), "Directory &amp; Path Discovery") ||
		!strings.Contains(htmlBuf.String(), "https://example.com/admin") {
		t.Fatalf("HTML report did not render path discovery section: %s", htmlBuf.String())
	}
}

func TestPartialReportFilters(t *testing.T) {
	db, scanID := setupReportDB(t, 10)
	defer db.Close()

	store := evidencestore.New(db)
	builder := NewBuilder(store, db)
	exporter := NewExporter(builder, nil)

	opts := Options{
		ScanID: scanID, Template: TemplateInternal, Format: FormatCSV,
		Severities: []string{"critical"}, Partial: true,
	}
	var buf bytes.Buffer
	if err := exporter.Export(&buf, opts); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	// header + critical only (every 4th in seed loop: 0,4,8 = 3 findings)
	if len(lines) != 4 {
		t.Fatalf("expected 4 csv lines for critical filter, got %d: %s", len(lines), buf.String())
	}
}

func TestDistinctTemplates(t *testing.T) {
	db, scanID := setupReportDB(t, 1)
	defer db.Close()
	store := evidencestore.New(db)
	builder := NewBuilder(store, db)
	exporter := NewExporter(builder, nil)

	templates := []TemplateKind{TemplateHackerOne, TemplateBugcrowd, TemplateInternal, TemplateExecutive, TemplateAppendix}
	seen := map[string]bool{}
	for _, tmpl := range templates {
		opts := Options{ScanID: scanID, Template: tmpl, Format: FormatHTML}
		var buf bytes.Buffer
		if err := exporter.Export(&buf, opts); err != nil {
			t.Fatal(err)
		}
		body := buf.String()
		if seen[body] {
			t.Fatalf("duplicate output for template %s", tmpl)
		}
		seen[body] = true
		switch tmpl {
		case TemplateHackerOne:
			if !strings.Contains(body, "Steps to Reproduce") {
				t.Fatal("hackerone missing reproduction section")
			}
		case TemplateBugcrowd:
			if !strings.Contains(body, "Proof of Concept") {
				t.Fatal("bugcrowd missing PoC section")
			}
		case TemplateExecutive:
			if !strings.Contains(body, "Executive Findings Overview") {
				t.Fatal("executive missing overview table")
			}
		case TemplateAppendix:
			if !strings.Contains(body, "Appendix") {
				t.Fatal("appendix missing appendix section")
			}
		}
	}
}

func TestLargeScanStreamingMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("large fixture")
	}
	db, scanID := setupReportDB(t, 1200)
	defer db.Close()

	store := evidencestore.New(db)
	builder := NewBuilder(store, db)
	exporter := NewExporter(builder, nil)
	opts := Options{ScanID: scanID, Template: TemplateInternal, Format: FormatCSV}

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	var buf bytes.Buffer
	if err := exporter.Export(&buf, opts); err != nil {
		t.Fatal(err)
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	lines := strings.Count(buf.String(), "\n")
	if lines < 1200 {
		t.Fatalf("expected 1200+ csv lines, got %d", lines)
	}
	// Heap growth should stay well below proportional load (1200 full finding structs in memory).
	growth := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	if growth > 50*1024*1024 {
		t.Fatalf("heap grew too much during streaming export: %d bytes", growth)
	}
}

func TestRedactionPreservesRawValues(t *testing.T) {
	in := "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.x and api_key=supersecretvalue"
	out := RedactString(in)
	if !strings.Contains(out, "supersecretvalue") || !strings.Contains(out, "eyJhbGci") {
		t.Fatalf("raw values were unexpectedly redacted: %s", out)
	}
}

func TestFindingWithoutRedactionPreservesRawValues(t *testing.T) {
	rec := storage.FindingRecord{
		Title:       "SQL Injection",
		VulnClass:   "sqli",
		Description: "password=' OR 1=1-- - Authorization: Bearer raw-token",
		Summary:     "password=' OR 1=1-- -",
	}
	entry := FindingFromRecord(rec, false)
	if strings.Contains(entry.Description, "[REDACTED]") ||
		!strings.Contains(entry.Description, "password=' OR 1=1-- -") ||
		!strings.Contains(entry.Description, "Bearer raw-token") {
		t.Fatalf("unredacted finding lost raw evidence: %s", entry.Description)
	}
}

func TestHTTPEvidenceResponseHighlightsOnlyTypedProof(t *testing.T) {
	body := `<!DOCTYPE html><html><head><meta content="674b8d5747-78dds">` +
		`<script src="https://cdn.example/app.bundle-a91cf778.js"></script></head>` +
		`<body>AKCA_CMD_7320</body></html>`
	ev := HTTPEvidence{
		Signal:      "canary_output",
		Payload:     `;printf 'AKCA_CMD_%d' $((7319+1))`,
		RespBody:    body,
		RawRequest:  "GET /?q=%3Bprintf HTTP/1.1\r\nHost: example.test\r\n\r\n",
		RawResponse: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + body,
		ResponseMarkers: []string{
			`<!DOCTYPE html><html><head>`,
			`674b8d5747-78dds`,
			`https://cdn.example/app.bundle-a91cf778.js`,
			`AKCA_CMD_7320`,
		},
	}
	html := httpEvidenceHTML(ev)
	// One highlight belongs to the payload box and one to the independently
	// computed response canary. No document or asset marker may be highlighted.
	if strings.Count(html, `class="vuln-hit"`) != 2 {
		t.Fatalf("expected payload plus one response proof highlight, got: %s", html)
	}
	if !strings.Contains(html, `<span class="vuln-hit">AKCA_CMD_7320</span>`) {
		t.Fatalf("expected command canary to be highlighted: %s", html)
	}
	for _, noise := range []string{
		`<span class="vuln-hit">&lt;!DOCTYPE`,
		`<span class="vuln-hit">674b8d5747-78dds`,
		`<span class="vuln-hit">https://cdn.example`,
	} {
		if strings.Contains(html, noise) {
			t.Fatalf("legacy HTML noise was highlighted: %s", noise)
		}
	}
}

func TestDashboardMetricsAndSearch(t *testing.T) {
	db, scanID := setupReportDB(t, 3)
	defer db.Close()
	m, err := db.DashboardMetrics(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if m.TotalFindings != 3 {
		t.Fatalf("expected 3 findings, got %d", m.TotalFindings)
	}
	results, err := db.SearchFindings(scanID, "Bearer", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("expected FTS search hit")
	}
}

func TestMigrationVersionLatest(t *testing.T) {
	db, scanID := setupReportDB(t, 1)
	defer db.Close()
	v, err := db.CurrentVersion()
	if err != nil {
		t.Fatal(err)
	}
	if v != 16 {
		t.Fatalf("expected migration version 16, got %d", v)
	}
	_ = scanID
}

func TestInternalReportSeparatesManualLeads(t *testing.T) {
	db, scanID := setupReportDB(t, 1)
	defer db.Close()
	if err := db.SeedFindingForTest(scanID, "Unverified lead", "low", "Potential",
		"ssrf", "heuristic only", "https://example.com/fetch"); err != nil {
		t.Fatal(err)
	}
	builder := NewBuilder(evidencestore.New(db), db)
	internal, err := builder.BuildMeta(Options{ScanID: scanID, Template: TemplateInternal, Redact: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(internal.ManualLeads) != 1 || internal.ManualLeads[0].SubmissionReady ||
		internal.ManualLeads[0].AutomaticallyProven {
		t.Fatalf("manual lead was not safely separated: %+v", internal.ManualLeads)
	}
	bounty, err := builder.BuildMeta(Options{ScanID: scanID, Template: TemplateHackerOne, Redact: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(bounty.ManualLeads) != 0 {
		t.Fatal("bug-bounty report metadata must not include unproven leads")
	}
}

func TestInternalHTMLRendersCompletePassiveFindingEvidence(t *testing.T) {
	db, scanID := setupReportDB(t, 0)
	defer db.Close()
	evidence := `{
	  "module":"security_headers",
	  "signal":"missing_content_security_policy",
	  "payload":{"value":"Content-Security-Policy"},
	  "location":"response_headers",
	  "request":{"method":"GET","url":"https://example.com/passive/headers"},
	  "response":{"status_code":200,"body":"passive response evidence"}
	}`
	if _, err := db.SaveFinding(scanID, "Missing Content-Security-Policy", "medium",
		"security_headers", "The response omits Content-Security-Policy.",
		"https://example.com/passive/headers", "", 0.7, evidence); err != nil {
		t.Fatal(err)
	}
	exporter := NewExporter(NewBuilder(evidencestore.New(db), db), nil)
	var buf bytes.Buffer
	if err := exporter.Export(&buf, Options{
		ScanID: scanID, Template: TemplateInternal, Format: FormatHTML, Redact: false,
	}); err != nil {
		t.Fatal(err)
	}
	html := buf.String()
	for _, want := range []string{
		"Passive &amp; Manual Findings",
		"Missing Content-Security-Policy",
		"The response omits Content-Security-Policy.",
		"https://example.com/passive/headers",
		"Potential",
		"Content-Security-Policy",
		"missing_content_security_policy",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("comprehensive HTML omitted passive finding detail %q", want)
		}
	}
}

func TestConfirmedLabelWithoutProofNeverLeavesManualLeads(t *testing.T) {
	db, scanID := setupReportDB(t, 1)
	defer db.Close()
	if err := db.SeedFindingForTest(scanID, "False confirmed label", "critical", "Confirmed",
		"sqli", "status-only heuristic", "https://example.com/item?id=1"); err != nil {
		t.Fatal(err)
	}
	builder := NewBuilder(evidencestore.New(db), db)
	exporter := NewExporter(builder, nil)

	for _, format := range []Format{FormatJSON, FormatCSV, FormatMarkdown, FormatSARIF, FormatHTML} {
		var buf bytes.Buffer
		if err := exporter.Export(&buf, Options{
			ScanID: scanID, Template: TemplateHackerOne, Format: format, Redact: true,
		}); err != nil {
			t.Fatalf("%s export failed: %v", format, err)
		}
		if strings.Contains(buf.String(), "False confirmed label") {
			t.Fatalf("%s leaked an unproven confirmed label", format)
		}
	}

	internal, err := builder.BuildMeta(Options{ScanID: scanID, Template: TemplateInternal, Redact: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(internal.ManualLeads) != 1 ||
		internal.ManualLeads[0].Finding.VulnClass != "sqli" ||
		internal.ManualLeads[0].SubmissionReady {
		t.Fatalf("unproven confirmed record was not quarantined: %+v", internal.ManualLeads)
	}
	if internal.Metrics.TotalFindings != 1 ||
		internal.Metrics.ByConfidence["Confirmed"] != 1 {
		t.Fatalf("unproven record polluted primary report metrics: %+v", internal.Metrics)
	}
}

func TestEvidenceLedgerIsGroupedByProofRole(t *testing.T) {
	raw := `{
	  "module":"sqli",
	  "verification":{
	    "proof_type":"boolean_pair",
	    "proof_policy_version":"v2",
	    "proof_satisfied":true,
	    "observations":[
	      {"id":"b","role":"native_baseline","attempt":1,"request_method":"GET","request_url":"https://e.test/","request_hash":"br","response_hash":"bs","normalized_hash":"bn","status_code":200},
	      {"id":"p","role":"positive_probe","attempt":1,"request_method":"GET","request_url":"https://e.test/?id=1","request_hash":"pr","response_hash":"ps","normalized_hash":"pn","status_code":200},
	      {"id":"c","role":"negative_control","attempt":1,"request_method":"GET","request_url":"https://e.test/?id=2","request_hash":"cr","response_hash":"cs","normalized_hash":"cn","status_code":200},
	      {"id":"o","role":"oast_callback","attempt":1,"oast_payload_id":"payload-1"}
	    ]
	  }
	}`
	ev := httpEvidenceFromRecord(storage.FindingRecord{EvidenceJSON: raw})
	if len(ev.Baseline) != 1 || len(ev.Probes) != 1 || len(ev.Controls) != 1 ||
		len(ev.ExternalProof) != 1 {
		t.Fatalf("evidence roles were not grouped: %+v", ev)
	}
}
