package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/akha-security/akca/engine/internal/storage"
)

// A realistic layout sample, separate from the extreme-input stress fixture.
// All findings are invented examples; no network requests are made.
func TestProfessionalReportPreview(t *testing.T) {
	meta := Document{
		Title: "Application security assessment", Summary: "Design preview · sample findings and HTTP evidence. No live target was scanned.",
		Template: TemplateInternal, EngineVersion: "v0.3.1", GeneratedAt: time.Date(2026, 11, 9, 10, 30, 0, 0, time.UTC),
		Scope: ScopeSection{Targets: []string{"https://app.example.test"}, ScanID: "sample-assessment"},
		Metrics: storage.DashboardMetrics{TotalFindings: 3, TotalRequests: 143, EndpointCount: 24,
			BySeverity: map[string]int{"high": 1, "medium": 1, "low": 1}, ByVulnClass: map[string]int{"sqli": 1, "cors": 1, "security_headers": 1}},
	}
	findings := []FindingEntry{
		{ID: 1, Title: "SQL injection in product category filter", VulnClass: "sqli", Severity: "High", Confidence: "Confirmed",
			EndpointURL: "https://app.example.test/api/products?category=1", Parameter: "category", CWE: []string{"CWE-89"},
			Description:       "The category filter passes user input into a database query. A specially crafted value produces a database syntax error in this sample response.",
			Impact:            "An attacker may be able to read or change application data through the affected query.",
			Remediation:       "Use parameterized queries and validate the category identifier on the server. Avoid returning database errors to clients.",
			ConfidenceExplain: "Sample evidence for design review; this is not a result from a real scan.",
			HTTPEvidence: HTTPEvidence{Method: "GET", URL: "https://app.example.test/api/products?category=1%27", StatusCode: 500, Location: "query", Parameter: "category", Payload: "1'", Signal: "database_error",
				RawRequest:      "GET /api/products?category=1%27 HTTP/1.1\r\nHost: app.example.test\r\nAccept: application/json\r\n\r\n",
				RawResponse:     "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\r\n{\"error\":\"SQLSTATE[42000]: syntax error near category\"}",
				ResponseMarkers: []string{"SQLSTATE[42000]"}}},
		{ID: 2, Title: "Credentialed CORS allows an untrusted origin", VulnClass: "cors", Severity: "Medium", Confidence: "Confirmed",
			EndpointURL: "https://app.example.test/api/profile", CWE: []string{"CWE-942"},
			Description: "The sample endpoint reflects an untrusted Origin value while allowing credentials in cross-origin requests.",
			Impact:      "A malicious website may be able to read private API responses using a signed-in user's session.",
			Remediation: "Allow only explicitly trusted origins. Enable credentialed cross-origin access only for endpoints that require it.",
			HTTPEvidence: HTTPEvidence{Method: "GET", StatusCode: 200, Signal: "origin_reflection",
				RawRequest:  "GET /api/profile HTTP/1.1\r\nHost: app.example.test\r\nOrigin: https://untrusted.example.test\r\n\r\n",
				RawResponse: "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: https://untrusted.example.test\r\nAccess-Control-Allow-Credentials: true\r\nContent-Type: application/json\r\n\r\n{\"name\":\"Sample user\"}"}},
		{ID: 3, Title: "Content Security Policy is not configured", VulnClass: "security_headers", Severity: "Low", Confidence: "Confirmed",
			EndpointURL: "https://app.example.test/", CWE: []string{"CWE-693"},
			Description: "The application response does not include a Content-Security-Policy header in this sample capture.",
			Impact:      "The browser has fewer restrictions on the scripts and resources the page can load.",
			Remediation: "Introduce a Content Security Policy in report-only mode, review violations, and enforce a policy appropriate for the application.",
			HTTPEvidence: HTTPEvidence{Method: "GET", StatusCode: 200, Signal: "missing_header",
				RawRequest:  "GET / HTTP/1.1\r\nHost: app.example.test\r\n\r\n",
				RawResponse: "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\n\r\n<!doctype html><title>Sample application</title>"}},
	}
	var page strings.Builder
	page.WriteString(htmlDocStart(meta))
	page.WriteString(`<section id="findings" class="report-section"><h2>Findings</h2>` + findingFilterControlsHTML("3 findings shown") + `<div class="findings-list">`)
	for _, finding := range findings {
		page.WriteString(findingHTML(finding, meta.Template))
	}
	page.WriteString(`</div></section>`)
	if err := renderHTMLSection(&page, "scope", "Scope", scopeHTML(meta.Scope)); err != nil {
		t.Fatal(err)
	}
	if err := renderHTMLSection(&page, "metrics", "Scan metrics", metricsHTML(meta.Metrics)); err != nil {
		t.Fatal(err)
	}
	page.WriteString(htmlDocEnd())
	if output := os.Getenv("AKCA_REPORT_PREVIEW_DIR"); output != "" {
		if err := os.MkdirAll(output, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(output, "report-preview.html"), []byte(page.String()), 0644); err != nil {
			t.Fatal(err)
		}
		mobile := `<!doctype html><html><head><title>Mobile report preview</title><meta name="viewport" content="width=device-width,initial-scale=1"></head><body style="margin:0;background:#f3f5f7"><iframe title="375px report preview" src="report-preview.html" style="display:block;width:375px;max-width:100%;height:1800px;border:0"></iframe></body></html>`
		if err := os.WriteFile(filepath.Join(output, "report-preview-mobile.html"), []byte(mobile), 0644); err != nil {
			t.Fatal(err)
		}
	}
}
