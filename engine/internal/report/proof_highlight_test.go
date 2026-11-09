package report

import (
	"net/url"
	"strings"
	"testing"
)

func TestRequestPanelShowsEncodedPayloadAndObservedSQLError(t *testing.T) {
	payload := "'; SELECT SLEEP(4)-- -"
	encoded := url.QueryEscape(payload)
	message := "You have an error in your SQL syntax"
	ev := HTTPEvidence{
		Signal: "error_based", Payload: payload, Parameter: "id", Method: "GET", StatusCode: 500,
		RawRequest:  "GET /search?id=" + encoded + " HTTP/1.1\r\nHost: example.test\r\n\r\n",
		RawResponse: "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\n\r\n<p>" + message + "</p>",
	}
	html := httpEvidenceHTML(ev)
	requestStart := strings.Index(html, `data-evidence-panel="request"`)
	responseStart := strings.Index(html, `data-evidence-panel="response"`)
	if requestStart < 0 || responseStart <= requestStart {
		t.Fatalf("request and response panels missing: %s", html)
	}
	requestPanel := html[requestStart:responseStart]
	if !strings.Contains(requestPanel, `<span class="vuln-hit">`+encoded+`</span>`) {
		t.Fatalf("wire-encoded payload was not highlighted in request: %s", requestPanel)
	}
	if !strings.Contains(requestPanel, `<span class="vuln-hit">`+message+`</span>`) {
		t.Fatalf("observed SQL error was not shown beside request: %s", requestPanel)
	}
	if !strings.Contains(html, `data-evidence-tab="both"`) || !strings.Contains(html, `data-evidence-panel="response"`) {
		t.Fatal("request and response are not available together")
	}
}

func TestResponseProofUsesRawTransactionWhenBodyFieldIsEmpty(t *testing.T) {
	html := httpEvidenceHTML(HTTPEvidence{
		Signal: "error_based", RawRequest: "GET /search?id=1 HTTP/1.1\r\n\r\n",
		RawResponse: "HTTP/1.1 500 Internal Server Error\r\n\r\nSQL syntax error near '1'",
	})
	if strings.Count(html, `<span class="vuln-hit">SQL syntax error</span>`) != 2 {
		t.Fatalf("raw response proof was not highlighted in request and response: %s", html)
	}
}

func TestModuleSpecificDatabaseErrorHighlightsObservedSyntax(t *testing.T) {
	html := httpEvidenceHTML(HTTPEvidence{
		Signal: "database_error", RawRequest: "GET /api?id=1%27 HTTP/1.1\r\n\r\n",
		RawResponse: "HTTP/1.1 500 Internal Server Error\r\n\r\nSQLSTATE[42000]: syntax error near category",
	})
	if !strings.Contains(html, `<span class="vuln-hit">SQLSTATE[42000]</span>`) {
		t.Fatalf("observed database syntax evidence was not highlighted: %s", html)
	}
}

func TestComparativeAndNonTextEvidenceIsClearlyLabeled(t *testing.T) {
	booleanHTML := httpEvidenceHTML(HTTPEvidence{
		RawRequest: "GET /search?id=1 HTTP/1.1\r\n\r\n", Signal: "boolean_pair_confirmed",
		ProofSummary: "True and false branches matched separate response hashes across two controls.",
	})
	if !strings.Contains(booleanHTML, `class="evidence-proof"`) ||
		!strings.Contains(booleanHTML, "Comparative evidence") ||
		!strings.Contains(booleanHTML, "two controls") {
		t.Fatalf("boolean comparison was not shown: %s", booleanHTML)
	}
	timingHTML := httpEvidenceHTML(HTTPEvidence{
		RawRequest: "GET /search?id=1 HTTP/1.1\r\n\r\n", Signal: "stacked_timing",
		SemanticDelta: map[string]interface{}{"control_ms": 120, "probe_ms": 4120},
	})
	if !strings.Contains(timingHTML, "Recorded verification data") ||
		!strings.Contains(timingHTML, "probe_ms") || strings.Contains(timingHTML, `<span class="vuln-hit">syntax`) {
		t.Fatalf("timing data was omitted or fabricated as response text: %s", timingHTML)
	}
	missingHeaderHTML := httpEvidenceHTML(HTTPEvidence{
		RawRequest: "GET / HTTP/1.1\r\n\r\n", RawResponse: "HTTP/1.1 200 OK\r\n\r\n",
		Signal: "missing_csp",
	})
	if !strings.Contains(missingHeaderHTML, "Recorded detection signal") ||
		!strings.Contains(missingHeaderHTML, "No exact response substring was stored") {
		t.Fatalf("absence finding was mislabeled as an exact response match: %s", missingHeaderHTML)
	}
}
