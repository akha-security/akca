package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/akha-security/akca/engine/internal/storage"
)

func TestCompactReportStringPreservesUTF8AndEvidenceTail(t *testing.T) {
	for offset := 0; offset < 8; offset++ {
		body := strings.Repeat("x", offset) + strings.Repeat("İstanbul-şğü-😀", 1500) + "END-OF-EVIDENCE"
		compact, truncated := compactReportString(body, 1024)
		if !truncated || !utf8.ValidString(compact) || len(compact) > 1024 || !strings.HasSuffix(compact, "END-OF-EVIDENCE") {
			t.Fatalf("invalid UTF-8 or lost evidence at offset %d", offset)
		}
	}
}

func TestLargeReportRetainsMiddleProofAndDoesNotHighlightMarkup(t *testing.T) {
	body := strings.Repeat("prefix ", 15000) + "EXACT-PRIVATE-PROOF-731" + strings.Repeat(" suffix", 15000)
	ev := compactHTTPEvidence(HTTPEvidence{Payload: "EXACT-PRIVATE-PROOF-731", RespBody: body, RawResponse: body, ResponseMarkers: []string{"EXACT-PRIVATE-PROOF-731"}})
	if strings.Contains(ev.RawResponse, "EXACT-PRIVATE-PROOF-731") || !strings.Contains(ev.MatchedExcerpt, "EXACT-PRIVATE-PROOF-731") {
		t.Fatal("middle evidence was lost or fixture did not exercise compaction")
	}
	out := highlightEvidence("private secret span class", []string{"private secret", "secret", "span", "class"})
	if strings.Count(out, `<span class="vuln-hit">`) != 3 || strings.Contains(out, `class="<span`) || strings.Contains(out, `<span <span`) {
		t.Fatalf("highlighting rewrote generated HTML: %s", out)
	}
}

func TestReportSeparatesRoutineDiagnosticsWithoutHidingCoverageIssues(t *testing.T) {
	html := coverageDiagnosticsHTML([]CoverageEntry{
		{EventType: "coverage_gap", Module: "sqli", Summary: "Required replay did not complete"},
		{EventType: "plugin_skipped", Module: "xss", Summary: "Static resource skipped"},
	})
	issue, details, routine := strings.Index(html, "Required replay did not complete"), strings.Index(html, `<details class="technical-details">`), strings.Index(html, "Static resource skipped")
	if issue < 0 || details < issue || routine < details || strings.Contains(html, `<details class="technical-details" open`) {
		t.Fatal("coverage issue hidden or routine diagnostic expanded")
	}
	raw := "HTTP/1.1 200 OK\n\nCAPTURED-RESPONSE"
	ev := httpEvidenceHTML(HTTPEvidence{Method: "GET", RawRequest: "GET /search HTTP/1.1", RawResponse: raw})
	if !strings.Contains(ev, `class="traffic-tab-panel compact active" data-evidence-panel="response"`) || !strings.Contains(ev, "CAPTURED-RESPONSE") {
		t.Fatal("response proof must be retained and compact by default")
	}
	f := FindingEntry{EndpointURL: "https://example.test/search?q=native", HTTPEvidence: HTTPEvidence{URL: "https://example.test/search?q=native", Method: "GET", StatusCode: 200}}
	if strings.Contains(findingMetaHTML(f), f.EndpointURL) {
		t.Fatal("same endpoint repeated in metadata")
	}
	f.HTTPEvidence.URL = "https://example.test/search?q=probe"
	if !strings.Contains(findingMetaHTML(f), f.HTTPEvidence.URL) {
		t.Fatal("different probe URL was hidden")
	}
}

// Produce a standalone, synthetic report for desktop/mobile visual QA. This
// never reads a user's scan database and never contacts a target.
func TestHTMLReportStressPreview(t *testing.T) {
	longURL := "https://report.example.test/api/search?context=" + strings.Repeat("long-url-value-", 55)
	body := strings.Repeat("const fixture='uzun-yanıt-İstanbul-şğü-😀';", 3200) + "\nMATCH-7319\nEND-OF-CAPTURE"
	meta := Document{Title: "Report layout preview", Summary: "Synthetic test data — no live target was scanned.", Template: TemplateInternal, EngineVersion: "v0.3.1", EngineCommit: "layout-preview", GeneratedAt: time.Now().UTC(), Partial: true,
		Scope:   ScopeSection{Targets: []string{longURL}, ScanID: "layout-preview"},
		Metrics: storage.DashboardMetrics{TotalFindings: 1, TotalRequests: 143, EndpointCount: 24, BySeverity: map[string]int{"high": 1}, ByVulnClass: map[string]int{"sqli": 1}}}
	f := FindingEntry{ID: 1, Title: "SQL Injection — synthetic evidence layout example", VulnClass: "sqli", Severity: "High", Confidence: "Confirmed", EndpointURL: longURL, Parameter: "context",
		Description: "This fixture exercises long URLs, unbroken text, Unicode and large stored responses. " + strings.Repeat("UzunMetin", 65),
		Impact:      "Demonstration content for report layout validation.", Remediation: "Review the input handler and apply the appropriate server-side fix.", ConfidenceExplain: "Synthetic verification metadata; this fixture is not a scan result.",
		HTTPEvidence: HTTPEvidence{Method: "GET", URL: longURL, StatusCode: 200, Parameter: "context", Payload: strings.Repeat("payload-şğü-", 25), Signal: "boolean_pair", RawRequest: "GET /api/search?context=" + strings.Repeat("query-value-", 110) + " HTTP/1.1\r\nHost: report.example.test\r\n\r\n", RawResponse: "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" + body, RespBody: body, ResponseMarkers: []string{"MATCH-7319"}}}
	var page strings.Builder
	page.WriteString(htmlDocStart(meta))
	_ = renderHTMLSection(&page, "scope", "Scope", scopeHTML(meta.Scope))
	page.WriteString(`<section id="findings" class="report-section"><h2>Findings</h2><div class="filter-controls"><input id="vulnSearch" type="text" placeholder="Search findings" oninput="applyFilters()"><span id="filterStatus"></span></div>` + findingHTML(f, TemplateInternal) + `</section>`)
	_ = renderHTMLSection(&page, "coverage", "Coverage diagnostics", coverageDiagnosticsHTML([]CoverageEntry{
		{EventType: "coverage_gap", Module: "ssrf", Endpoint: longURL, Summary: "A verification request did not finish; coverage is incomplete", Reason: "request_budget"},
		{EventType: "plugin_skipped", Module: "xss", Endpoint: longURL, Summary: "Static resource skipped", Reason: "static_resource"},
	}))
	_ = renderHTMLSection(&page, "path-discovery", "Directory & Path Discovery", pathDiscoveryHTML([]PathDiscoveryEntry{{Method: "GET", URL: longURL, StatusCode: 200, Category: "application", Signal: "reachable", BodyLength: 2048}}))
	page.WriteString(htmlDocEnd())
	html := page.String()
	if !utf8.ValidString(html) || strings.Contains(html, "%!") || !strings.Contains(html, "END-OF-CAPTURE") {
		t.Fatal("invalid report output or missing evidence tail")
	}
	if output := os.Getenv("AKCA_REPORT_PREVIEW_DIR"); output != "" {
		if err := os.MkdirAll(output, 0755); err != nil {
			t.Fatal(err)
		}
		qa := `<output id="qa-status" style="position:fixed;bottom:4px;left:4px;z-index:9999;background:#112;color:#fff;padding:4px;font:12px monospace"></output><script>function qa(){const w=document.documentElement.clientWidth,s=document.documentElement.scrollWidth;document.getElementById('qa-status').textContent='Viewport '+w+'px / document '+s+'px / overflow '+(s-w)+'px';}window.addEventListener('load',qa);window.addEventListener('resize',qa);document.addEventListener('click',()=>setTimeout(qa,30));</script>`
		preview := strings.Replace(html, "</body>", qa+"</body>", 1)
		if err := os.WriteFile(filepath.Join(output, "report-stress.html"), []byte(preview), 0644); err != nil {
			t.Fatal(err)
		}
		mobile := `<!doctype html><html><head><title>Mobile report stress test</title><meta name="viewport" content="width=device-width,initial-scale=1"></head><body style="margin:0;background:#ddd"><iframe title="375px report stress test" src="report-stress.html" style="display:block;width:375px;height:1800px;border:0"></iframe></body></html>`
		if err := os.WriteFile(filepath.Join(output, "report-stress-mobile.html"), []byte(mobile), 0644); err != nil {
			t.Fatal(err)
		}
		t.Log(fmt.Sprintf("Synthetic stress preview: %s", filepath.Join(output, "report-stress.html")))
	}
}
