package report

import (
	"encoding/json"
	"html/template"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/evidencemarkers"
)

// Request payloads are frequently URL- or JSON-encoded in the captured wire
// request. Highlight only an encoding that is actually present there.
func requestEvidenceMarkers(ev HTTPEvidence) []string {
	payload := ev.Payload
	if strings.TrimSpace(payload) == "" || ev.RawRequest == "" {
		return nil
	}
	quoted, _ := json.Marshal(payload)
	variants := []string{payload, url.QueryEscape(payload), url.PathEscape(payload)}
	variants = append(variants, strings.ReplaceAll(url.QueryEscape(payload), "+", "%20"))
	if len(quoted) >= 2 {
		variants = append(variants, string(quoted[1:len(quoted)-1]))
	}
	var markers []string
	for _, candidate := range variants {
		if len(candidate) < 3 {
			if ev.Parameter != "" {
				candidate = ev.Parameter + "=" + candidate
			} else {
				continue
			}
		}
		if strings.Contains(ev.RawRequest, candidate) {
			markers = append(markers, candidate)
		}
	}
	return markers
}

func responseEvidenceMarkers(ev HTTPEvidence, response string) []string {
	return evidencemarkers.ForReport(ev.Payload, ev.Signal, response, ev.ResponseMarkers)
}

// An exact response excerpt belongs beside the request that produced it.
// Comparative and timing findings instead show their stored verification data;
// no response substring is invented for those classes.
func requestProofHTML(ev HTTPEvidence, response string, markers []string) string {
	proofSource := response
	if ev.MatchedExcerpt != "" {
		proofSource = ev.MatchedExcerpt
		markers = responseEvidenceMarkers(ev, proofSource)
	}
	if excerpt := matchedReportExcerpt(proofSource, markers); excerpt != "" {
		return `<div class="evidence-proof"><strong>Observed response evidence</strong><pre class="http">` +
			highlightEvidence(template.HTMLEscapeString(excerpt), markers) + `</pre></div>`
	}
	if ev.ProofSummary != "" {
		return `<div class="evidence-proof"><strong>Comparative evidence</strong><p>` +
			template.HTMLEscapeString(ev.ProofSummary) + `</p></div>`
	}
	if len(ev.SemanticDelta) > 0 {
		encoded, err := json.MarshalIndent(ev.SemanticDelta, "", "  ")
		if err == nil {
			text, _ := compactReportString(string(encoded), 2048)
			return `<div class="evidence-proof"><strong>Recorded verification data</strong><pre class="http">` +
				template.HTMLEscapeString(text) + `</pre></div>`
		}
	}
	if ev.Signal != "" {
		return `<div class="evidence-proof"><strong>Recorded detection signal</strong><p><code>` +
			template.HTMLEscapeString(ev.Signal) + `</code></p><small>No exact response substring was stored for this finding. Review the captured transaction and verification details.</small></div>`
	}
	return `<p class="evidence-notice">No exact proof text was stored for highlighting.</p>`
}
