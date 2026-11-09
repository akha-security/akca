package report

import (
	"fmt"
	"html/template"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/akha-security/akca/engine/internal/evidencemarkers"
	"github.com/akha-security/akca/engine/internal/findingtext"
	"github.com/akha-security/akca/engine/internal/storage"
)

type vulnerabilityCount struct {
	Class string
	Label string
	Count int
}

func vulnerabilityOverviewHTML(metrics storage.DashboardMetrics) string {
	items := make([]vulnerabilityCount, 0, len(metrics.ByVulnClass))
	for class, count := range metrics.ByVulnClass {
		if count <= 0 {
			continue
		}
		items = append(items, vulnerabilityCount{
			Class: class,
			Label: findingtext.HumanTitle(class),
			Count: count,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return items[i].Label < items[j].Label
		}
		return items[i].Count > items[j].Count
	})

	var b strings.Builder
	if len(items) == 0 {
		return ""
	}
	b.WriteString(`<section class="class-overview"><h2>Finding categories</h2><div class="category-list">`)
	for _, item := range items {
		b.WriteString(`<button type="button" class="category-chip" aria-pressed="false" data-vclass="` + template.HTMLEscapeString(item.Class) + `" onclick="setClassFilter(this.dataset.vclass)">` + template.HTMLEscapeString(item.Label) + `<strong>` + fmt.Sprint(item.Count) + `</strong></button>`)
	}
	b.WriteString(`</div></section>`)
	return b.String()
}

func htmlDocStart(meta Document) string {
	return professionalDocStart(meta)
}

func htmlDocEnd() string {
	return `<footer class="report-footer"><span>AKCA</span><span>Security assessment report</span></footer></div>
<script>
// Theme Management
function initTheme() {
    document.documentElement.setAttribute('data-theme', 'light');
}

// Findings Filtering & Search
let activeSeverity = 'all';
let activeClass = 'all';

function setSeverityFilter(sev, btn) {
    activeSeverity = (sev || 'all').toLowerCase();
    if (activeSeverity === 'all') activeClass = 'all';
    document.querySelectorAll('.filter-btn[data-sev]').forEach(b => {
        const selected = b.getAttribute('data-sev') === activeSeverity;
        b.classList.toggle('active', selected);
        b.setAttribute('aria-pressed', String(selected));
    });
    applyFilters();
}

function setClassFilter(vulnClass) {
    const nextClass = (vulnClass || 'all').toLowerCase();
    activeClass = activeClass === nextClass ? 'all' : nextClass;
    applyFilters();
    const findingsEl = document.getElementById('findings') || document.querySelector('.findings-list');
    if (findingsEl) findingsEl.scrollIntoView({behavior: 'smooth', block: 'start'});
}

function applyFilters() {
    const searchInput = document.getElementById('vulnSearch');
    const q = searchInput ? searchInput.value.toLowerCase().trim() : '';
    document.querySelectorAll('.category-chip').forEach(chip => {
        chip.setAttribute('aria-pressed', String((chip.getAttribute('data-vclass') || '').toLowerCase() === activeClass));
    });
    let visible = 0;
    
    document.querySelectorAll('.finding').forEach(card => {
        const searchable = card.textContent.toLowerCase();
        const vulnClass = (card.getAttribute('data-class') || '').toLowerCase();
        const severity = (card.getAttribute('data-severity') || '').toLowerCase();
        
        const matchesQuery = !q || searchable.includes(q) || vulnClass.includes(q);
        const matchesSeverity = activeSeverity === 'all' || severity === activeSeverity;
        const matchesClass = activeClass === 'all' || vulnClass === activeClass;
        
        if (matchesQuery && matchesSeverity && matchesClass) {
            card.style.display = 'block';
            visible++;
        } else {
            card.style.display = 'none';
        }
    });
    
    const status = document.getElementById('filterStatus');
    if (status) status.textContent = visible + ' finding' + (visible === 1 ? '' : 's') + ' shown';
}

function toggleAllDetails(expand) {
    document.querySelectorAll('.finding details').forEach(d => {
        d.open = expand;
    });
}

function selectEvidenceTab(button, panelName) {
    const detail = button ? button.closest('.traffic-detail') : null;
    if (!detail) return;
    detail.querySelectorAll('.traffic-tab').forEach(tab => {
        const selected = tab.getAttribute('data-evidence-tab') === panelName;
        tab.classList.toggle('active', selected);
        tab.setAttribute('aria-pressed', String(selected));
    });
    detail.querySelectorAll('.traffic-tab-panel').forEach(panel => {
        panel.classList.toggle('active', panelName === 'both' || panel.getAttribute('data-evidence-panel') === panelName);
    });
}

function toggleEvidenceSize(button) {
    const panel = button.closest('.traffic-tab-panel');
    if (!panel) return;
    const isCompact = panel.classList.toggle('compact');
    button.setAttribute('aria-expanded', String(!isCompact));
    button.textContent = isCompact ? 'Show full content' : 'Compact view';
}

function showToast(msg) {
    let t = document.getElementById('akca-toast');
    if (!t) {
        t = document.createElement('div');
        t.id = 'akca-toast';
        document.body.appendChild(t);
    }
    t.textContent = msg;
    t.classList.add('show');
    setTimeout(() => { t.classList.remove('show'); }, 2000);
}

function copyToClipboard(btn, text) {
    if (text == null && btn) {
        const explicit = btn.getAttribute('data-copy');
        const header = btn.closest('.code-header, .evidence-toolbar');
        const block = header ? header.nextElementSibling : btn.nextElementSibling;
        text = explicit !== null ? explicit : (block ? block.textContent : '');
    }
    if (text == null || text === '') { showToast('Nothing to copy'); return; }
    const fallback = () => {
        const field = document.createElement('textarea');
        field.value = text;
        field.style.position = 'fixed';
        field.style.opacity = '0';
        const previous = document.activeElement;
        document.body.appendChild(field);
        try {
            field.select();
            if (!document.execCommand('copy')) throw new Error('Copy unavailable');
        } finally {
            field.remove();
            if (previous && previous.focus) previous.focus();
        }
    };
    const operation = navigator.clipboard && navigator.clipboard.writeText
        ? Promise.resolve().then(() => navigator.clipboard.writeText(text)).catch(fallback)
        : Promise.resolve().then(fallback);
    return operation.then(() => {
        if (btn) {
            const orig = btn.innerHTML;
            btn.innerHTML = '✓ Copied!';
            btn.classList.add('copied');
            setTimeout(() => {
                btn.innerHTML = orig;
                btn.classList.remove('copied');
            }, 1800);
        }
        showToast('✓ Copied to clipboard!');
    }).catch(() => {
        showToast('Failed to copy');
    });
}

document.addEventListener('DOMContentLoaded', initTheme);
document.documentElement.classList.add('js-ready');
initTheme();
let printClosedDetails = [];
window.addEventListener('beforeprint', () => {
    printClosedDetails = Array.from(document.querySelectorAll('details:not([open])'));
    printClosedDetails.forEach(detail => { detail.open = true; });
});
window.addEventListener('afterprint', () => {
    printClosedDetails.forEach(detail => { detail.open = false; });
    printClosedDetails = [];
});
</script>
<div id="akca-toast">✓ Copied to clipboard!</div>
</body></html>`
}

func renderHTMLSection(w io.Writer, id, title, body string) error {
	if id == "scope" || id == "metrics" || id == "root_cause" {
		_, err := fmt.Fprintf(w, `<section id="%s" class="report-section"><details class="section-disclosure"><summary>%s</summary><div class="card">%s</div></details></section>`, template.HTMLEscapeString(id), template.HTMLEscapeString(title), body)
		return err
	}
	_, err := fmt.Fprintf(w, `<section id="%s" class="report-section"><h2>%s</h2><div class="card">%s</div></section>`,
		id, template.HTMLEscapeString(title), body)
	return err
}

func scopeHTML(s ScopeSection) string {
	var b strings.Builder
	b.WriteString("<ul class=\"scope\">")
	for _, t := range s.Targets {
		b.WriteString("<li>" + template.HTMLEscapeString(t) + "</li>")
	}
	b.WriteString("</ul><p class=\"meta-line\">Scan ID: <code>" + template.HTMLEscapeString(s.ScanID) + "</code></p>")
	return b.String()
}

func metricsHTML(m storage.DashboardMetrics) string {
	return fmt.Sprintf(`<div class="metrics">
<div class="metric"><div class="n">%d</div><div class="l">Findings</div></div>
<div class="metric"><div class="n">%d</div><div class="l">Requests Sent</div></div>
<div class="metric"><div class="n">%d</div><div class="l">Endpoints</div></div>
<div class="metric"><div class="n">%d</div><div class="l">Evidence</div></div>
<div class="metric"><div class="n">%d</div><div class="l">OAST</div></div>
</div>`,
		m.TotalFindings, m.TotalRequests, m.EndpointCount, m.EvidenceCount, m.OASTCallbacks)
}

func apiKeysHTML(keys []APIKeySection) string {
	if len(keys) == 0 {
		return "<p class=\"meta-line\">No API key validation results recorded.</p>"
	}
	var b strings.Builder
	b.WriteString("<table class=\"data\"><thead><tr><th>Service</th><th>Status</th><th>Risk</th><th>Remediation</th></tr></thead><tbody>")
	for _, k := range keys {
		b.WriteString(fmt.Sprintf("<tr><td><strong>%s</strong></td><td>%s</td><td>%s</td><td>%s</td></tr>",
			template.HTMLEscapeString(k.Service),
			template.HTMLEscapeString(k.Status),
			template.HTMLEscapeString(k.Risk),
			template.HTMLEscapeString(k.Remediation)))
	}
	b.WriteString("</tbody></table>")
	return scrollTableHTML(b.String())
}

func rootCauseHTML(groups []storage.FindingGroupRecord) string {
	var b strings.Builder
	b.WriteString("<ul>")
	for _, g := range groups {
		b.WriteString("<li><strong>" + template.HTMLEscapeString(g.RootCause) + "</strong></li>")
	}
	b.WriteString("</ul>")
	return b.String()
}

func findingHTML(f FindingEntry, kind TemplateKind) string {
	sevKey := strings.ToLower(f.Severity)
	if sevKey == "" {
		sevKey = "info"
	}
	var b strings.Builder
	b.WriteString(`<article class="finding sev-` + template.HTMLEscapeString(sevKey) +
		`" data-severity="` + template.HTMLEscapeString(sevKey) +
		`" data-class="` + template.HTMLEscapeString(f.VulnClass) + `">`)
	b.WriteString(`<div class="finding-header"><div class="finding-title-row"><span class="finding-id">Finding #` + fmt.Sprint(f.ID) + `</span><h3>` +
		template.HTMLEscapeString(f.Title) + `</h3></div><div class="finding-badges"><span class="badge badge-` + template.HTMLEscapeString(sevKey) + `">` +
		template.HTMLEscapeString(f.Severity) + `</span><span class="badge">` +
		template.HTMLEscapeString(f.Confidence) + `</span></div></div>`)
	if f.EndpointURL != "" || f.HTTPEvidence.URL != "" {
		method := f.HTTPEvidence.Method
		if method == "" {
			method = "HTTP"
		}
		endpoint := f.EndpointURL
		if endpoint == "" {
			endpoint = f.HTTPEvidence.URL
		}
		displayEndpoint, long := endpointPresentation(endpoint)
		b.WriteString(`<div class="finding-endpoint"><span class="method">` + template.HTMLEscapeString(method) +
			`</span><code>` + template.HTMLEscapeString(displayEndpoint) + `</code></div>`)
		if long {
			b.WriteString(`<details class="endpoint-details"><summary>Full endpoint URL</summary><pre class="http">` + template.HTMLEscapeString(endpoint) + `</pre></details>`)
		}
	}
	if f.Parameter != "" {
		b.WriteString(`<p class="finding-context"><span>Parameter <code>` + template.HTMLEscapeString(f.Parameter) + `</code></span><span>` + template.HTMLEscapeString(f.HTTPEvidence.Location) + `</span></p>`)
	}
	var classification strings.Builder
	if len(f.CWE) > 0 || len(f.OWASPTop102025) > 0 {
		classification.WriteString(`<div class="classification-strip">`)
		if len(f.CWE) > 0 {
			classification.WriteString(`<span>CWE: ` + template.HTMLEscapeString(strings.Join(f.CWE, ", ")) + `</span>`)
		}
		if len(f.OWASPTop102025) > 0 {
			classification.WriteString(`<span>OWASP: ` + template.HTMLEscapeString(strings.Join(f.OWASPTop102025, ", ")) + `</span>`)
		}
		classification.WriteString(`</div>`)
	}

	b.WriteString(`<div class="finding-section-grid">`)
	switch kind {
	case TemplateHackerOne:
		b.WriteString(`<section class="finding-section"><h4>Weakness</h4><p>` + template.HTMLEscapeString(f.Description) + `</p></section>`)
		b.WriteString(`<section class="finding-section"><h4>Steps to Reproduce</h4><ol>`)
		for _, s := range f.ReproductionSteps {
			b.WriteString("<li>" + template.HTMLEscapeString(s) + "</li>")
		}
		b.WriteString("</ol></section>")
	case TemplateBugcrowd:
		b.WriteString(`<section class="finding-section"><h4>Description</h4><p>` + template.HTMLEscapeString(f.Description) + `</p></section>`)
		b.WriteString(`<section class="finding-section"><h4>Proof of Concept</h4><p>See the affected instance and HTTP evidence below.</p><h4>Impact</h4><p>` + template.HTMLEscapeString(f.Impact) + `</p></section>`)
	default:
		b.WriteString(`<section class="finding-section"><h4>Vulnerability Description</h4><p>` + template.HTMLEscapeString(f.Description) + `</p></section>`)
		b.WriteString(`<section class="finding-section"><h4>Impact</h4><p>` + template.HTMLEscapeString(f.Impact) + `</p></section>`)
	}
	b.WriteString(`</div>`)
	if kind == TemplateHackerOne {
		b.WriteString("<h4>Impact</h4><p>" + template.HTMLEscapeString(f.Impact) + "</p>")
	}
	if kind != TemplateHackerOne {
		b.WriteString(`<section class="finding-section recommendation"><h4>Recommendation</h4><p>` +
			template.HTMLEscapeString(f.Remediation) + `</p></section>`)
	}
	b.WriteString(`<details class="finding-evidence"><summary>Technical evidence</summary>`)
	b.WriteString(findingMetaHTML(f))
	b.WriteString(classification.String())
	b.WriteString(httpEvidenceHTML(f.HTTPEvidence))
	if f.ConfidenceExplain != "" {
		b.WriteString(`<p class="verification-note">` + template.HTMLEscapeString(f.ConfidenceExplain) + `</p>`)
	}
	b.WriteString(`</details>`)
	b.WriteString("</article>")
	return b.String()
}

func findingMetaHTML(f FindingEntry) string {
	var b strings.Builder
	b.WriteString(`<dl class="kv">`)
	if f.Parameter != "" {
		b.WriteString(`<dt>Parameter</dt><dd><strong>` + template.HTMLEscapeString(f.Parameter) + `</strong></dd>`)
	}
	if f.HTTPEvidence.Location != "" {
		b.WriteString(`<dt>Location</dt><dd>` + template.HTMLEscapeString(f.HTTPEvidence.Location) + `</dd>`)
	}
	if f.HTTPEvidence.URL != "" && f.HTTPEvidence.URL != f.EndpointURL {
		b.WriteString(`<dt>Request</dt><dd>` + template.HTMLEscapeString(f.HTTPEvidence.Method+" "+f.HTTPEvidence.URL) + `</dd>`)
	}
	if f.HTTPEvidence.StatusCode > 0 {
		b.WriteString(`<dt>Status</dt><dd>` + template.HTMLEscapeString(fmt.Sprintf("%d", f.HTTPEvidence.StatusCode)) + `</dd>`)
	}
	if f.HTTPEvidence.Signal != "" {
		b.WriteString(`<dt>Detection</dt><dd>` + template.HTMLEscapeString(f.HTTPEvidence.Signal) + `</dd>`)
	}
	b.WriteString(`</dl>`)
	return b.String()
}

func httpEvidenceHTML(ev HTTPEvidence) string {
	ev = compactHTTPEvidence(ev)
	if ev.RawRequest == "" && ev.RawResponse == "" && ev.RespBody == "" && ev.CurlCommand == "" && ev.Payload == "" &&
		ev.Signal == "" && ev.ProofSummary == "" && len(ev.SemanticDelta) == 0 {
		return `<h4>HTTP Evidence</h4><p class="evidence-notice">No HTTP request or response was stored for this finding.</p>`
	}
	var b strings.Builder
	b.WriteString(`<h4>HTTP Evidence</h4>`)
	if ev.Payload != "" {
		paramLabel := "Payload tested"
		if ev.Parameter != "" {
			paramLabel = fmt.Sprintf("Payload tested on parameter %q", ev.Parameter)
		}
		b.WriteString(`<p><strong>` + template.HTMLEscapeString(paramLabel) + `</strong></p><div class="payload-box">` +
			highlightEvidence(template.HTMLEscapeString(ev.Payload), []string{ev.Payload}) + `</div>`)
	}
	if ev.OASTURL != "" {
		b.WriteString(`<p><strong>OAST URL</strong> <code>` + template.HTMLEscapeString(ev.OASTURL) + `</code></p>`)
	}
	if ev.ProofSummary != "" {
		b.WriteString(`<p><strong>Comparative proof</strong>: ` + template.HTMLEscapeString(ev.ProofSummary) + `</p>`)
	}
	if ev.MatchedExcerpt != "" {
		excerptMarkers := evidencemarkers.ForReport(ev.Payload, ev.Signal, ev.MatchedExcerpt, ev.ResponseMarkers)
		b.WriteString(`<p><strong>Matched evidence excerpt</strong></p><pre class="http">` + highlightEvidence(template.HTMLEscapeString(ev.MatchedExcerpt), excerptMarkers) + `</pre>`)
	}
	if len(ev.Observations) > 0 {
		var counts []string
		for _, item := range []struct {
			count int
			label string
		}{
			{len(ev.Baseline), "baseline"}, {len(ev.Probes), "probe"}, {len(ev.Controls), "control"}, {len(ev.Replays), "replay"},
			{len(ev.State), "state"}, {len(ev.Identity), "identity"}, {len(ev.ExternalProof), "external"},
		} {
			if item.count > 0 {
				counts = append(counts, fmt.Sprintf("%d %s", item.count, item.label))
			}
		}
		b.WriteString(`<p><strong>Evidence ledger</strong>: ` + strings.Join(counts, " · ") + `</p>`)
		b.WriteString(`<details><summary>Show typed observations</summary><pre class="http">`)
		for _, observation := range ev.Observations {
			b.WriteString(template.HTMLEscapeString(fmt.Sprintf(
				"%s #%d %s %s status=%d request=%s response=%s normalized=%s\n",
				observation.Role, observation.Attempt, observation.RequestMethod,
				observation.RequestURL, observation.StatusCode,
				shortReportHash(observation.RequestHash), shortReportHash(observation.ResponseHash),
				shortReportHash(observation.NormalizedHash),
			)))
		}
		b.WriteString(`</pre></details>`)
	}
	if ev.ResourceReference != "" {
		b.WriteString(`<details><summary>Authenticated private-resource reference</summary><pre class="http">` + template.HTMLEscapeString(ev.ResourceReference) + `</pre></details>`)
	}
	if len(ev.ControlRequests) > 0 {
		b.WriteString(`<details><summary>Negative control requests</summary>`)
		for _, request := range ev.ControlRequests {
			b.WriteString(`<pre class="http">` + template.HTMLEscapeString(request) + `</pre>`)
		}
		b.WriteString(`</details>`)
	}
	if ev.ScreenshotRef != "" {
		b.WriteString(`<p><strong>Browser screenshot</strong>: <code>` +
			template.HTMLEscapeString(ev.ScreenshotRef) + `</code></p>`)
	}
	if ev.DOMSnapshotRef != "" {
		b.WriteString(`<p><strong>DOM snapshot</strong>: <code>` +
			template.HTMLEscapeString(ev.DOMSnapshotRef) + `</code></p>`)
	}
	responseEvidence := ev.RawResponse
	responseLabel := "Stored headers and body"
	if responseEvidence == "" {
		responseEvidence = ev.RespBody
		responseLabel = "Response excerpt (full transaction not stored)"
	}
	markers := responseEvidenceMarkers(ev, responseEvidence)
	proofHTML := requestProofHTML(ev, responseEvidence, markers)
	if ev.BodyTruncated {
		b.WriteString(`<p class="evidence-notice">The response exceeded the capture limit. All stored content is shown below; the uncaptured remainder is unavailable.</p>`)
	}
	if ev.ReportTruncated {
		b.WriteString(`<p class="evidence-notice">The report contains a compact response excerpt. The complete stored transaction remains available in the local evidence database.</p>`)
	}
	if ev.RawRequest == "" {
		b.WriteString(`<p class="evidence-notice">Request: no HTTP request was stored for this finding.</p>`)
	}
	if responseEvidence == "" {
		b.WriteString(`<p class="evidence-notice">Response: no HTTP response was stored for this finding.</p>`)
	}
	if ev.RawRequest != "" || responseEvidence != "" {
		defaultTab := "response"
		if ev.RawRequest != "" && responseEvidence != "" {
			defaultTab = "both"
		} else if responseEvidence == "" {
			defaultTab = "request"
		}
		b.WriteString(`<div class="traffic-detail"><div class="traffic-tabs">`)
		if ev.RawRequest != "" {
			active := ""
			if defaultTab == "request" {
				active = " active"
			}
			b.WriteString(`<button type="button" class="traffic-tab` + active + `" aria-pressed="` + fmt.Sprint(defaultTab == "request") + `" data-evidence-tab="request" onclick="selectEvidenceTab(this,'request')">Request</button>`)
		}
		if responseEvidence != "" {
			active := ""
			if defaultTab == "response" {
				active = " active"
			}
			b.WriteString(`<button type="button" class="traffic-tab` + active + `" aria-pressed="` + fmt.Sprint(defaultTab == "response") + `" data-evidence-tab="response" onclick="selectEvidenceTab(this,'response')">Response</button>`)
		}
		if ev.RawRequest != "" && responseEvidence != "" {
			active := ""
			if defaultTab == "both" {
				active = " active"
			}
			b.WriteString(`<button type="button" class="traffic-tab` + active + `" aria-pressed="` + fmt.Sprint(defaultTab == "both") + `" data-evidence-tab="both" onclick="selectEvidenceTab(this,'both')">Both</button>`)
		}
		b.WriteString(`</div>`)
		if ev.RawRequest != "" {
			active := ""
			if defaultTab == "request" || defaultTab == "both" {
				active = " active"
			}
			method := ev.Method
			if method == "" {
				method = "HTTP"
			}
			b.WriteString(`<div class="traffic-tab-panel compact` + active + `" data-evidence-panel="request"><div class="evidence-toolbar"><div class="evidence-context"><span class="evidence-direction">OUTBOUND</span><span class="evidence-method">` + template.HTMLEscapeString(method) + `</span><span>Captured transaction · Request</span></div>` + evidenceActionsHTML() + `</div><pre class="http">` +
				highlightEvidence(template.HTMLEscapeString(ev.RawRequest), requestEvidenceMarkers(ev)) + `</pre>` + proofHTML + `</div>`)
		}
		if responseEvidence != "" {
			active := ""
			if defaultTab == "response" || defaultTab == "both" {
				active = " active"
			}
			status := "Response"
			if ev.StatusCode > 0 {
				status = fmt.Sprintf("Status %d", ev.StatusCode)
			}
			b.WriteString(`<div class="traffic-tab-panel compact` + active + `" data-evidence-panel="response"><div class="evidence-toolbar"><div class="evidence-context"><span class="evidence-direction">INBOUND</span><span class="evidence-status">` + template.HTMLEscapeString(status) + `</span><span>` + template.HTMLEscapeString(responseLabel) + `</span></div>` + evidenceActionsHTML() + `</div><pre class="http">` +
				highlightEvidence(template.HTMLEscapeString(responseEvidence), markers) + `</pre></div>`)
		}
		b.WriteString(`</div>`)
		if ev.RawRequest == "" {
			b.WriteString(proofHTML)
		}
	} else {
		b.WriteString(proofHTML)
	}
	if ev.CurlCommand != "" {
		b.WriteString(`<details><summary>cURL reproduction command</summary><div class="code-header"><span>Stored reproduction command</span><button type="button" class="copy-btn" onclick="copyToClipboard(this)">Copy cURL</button></div><pre class="http">` + template.HTMLEscapeString(ev.CurlCommand) + `</pre></details>`)
	}
	return b.String()
}

func evidenceActionsHTML() string {
	return `<div class="evidence-actions"><button type="button" class="copy-btn" aria-expanded="false" onclick="toggleEvidenceSize(this)">Show full content</button><button type="button" class="copy-btn" onclick="copyToClipboard(this)">Copy</button></div>`
}

func shortReportHash(value string) string {
	if len(value) <= 12 {
		return value
	}
	return value[:12]
}

func trafficHTML(entries []TrafficEntry) string {
	if len(entries) == 0 {
		return `<div class="card"><p>No crawling traffic recorded.</p></div>`
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf(`<details class="technical-details"><summary>Captured crawler traffic (%d)</summary>`, len(entries)))
	for _, entry := range entries {
		request, _ := compactReportString(entry.RawRequest, reportRequestEvidenceLimit)
		response, _ := compactReportString(entry.RawResponse, reportResponseEvidenceLimit)
		b.WriteString(`<div class="card"><p><strong>` + template.HTMLEscapeString(entry.Method+" "+entry.URL) + `</strong> — ` + fmt.Sprintf("%d", entry.StatusCode) + `</p>`)
		b.WriteString(`<details><summary>Show Raw HTTP Request</summary><pre class="http">` + template.HTMLEscapeString(request) + `</pre></details>`)
		b.WriteString(`<details><summary>Show Raw HTTP Response</summary><pre class="http">` + template.HTMLEscapeString(response) + `</pre></details></div>`)
	}
	b.WriteString(`</details>`)
	return b.String()
}

func pathDiscoveryHTML(entries []PathDiscoveryEntry) string {
	if len(entries) == 0 {
		return `<p class="meta-line">No directory or path fuzzing discoveries recorded.</p>`
	}
	var b strings.Builder
	b.WriteString(`<table class="data"><thead><tr><th>Method</th><th>URL</th><th>Status</th><th>Category</th><th>Signal</th><th>Size</th></tr></thead><tbody>`)
	for _, entry := range entries {
		signal := entry.Signal
		if entry.IsArchive && signal == "" {
			signal = "archive_exposure"
		}
		b.WriteString(fmt.Sprintf("<tr><td>%s</td><td><code>%s</code></td><td>%d</td><td>%s</td><td>%s</td><td>%d</td></tr>",
			template.HTMLEscapeString(entry.Method),
			template.HTMLEscapeString(entry.URL),
			entry.StatusCode,
			template.HTMLEscapeString(entry.Category),
			template.HTMLEscapeString(signal),
			entry.BodyLength,
		))
	}
	b.WriteString(`</tbody></table>`)
	return fmt.Sprintf(`<details class="technical-details"><summary>Discovered paths (%d)</summary>%s</details>`, len(entries), scrollTableHTML(b.String()))
}

func coverageDiagnosticsHTML(entries []CoverageEntry) string {
	if len(entries) == 0 {
		return `<p class="meta-line">No coverage limitations or suppressed verification candidates were recorded.</p>`
	}
	var issues, diagnostics []CoverageEntry
	for _, entry := range entries {
		switch entry.EventType {
		case "coverage_gap", "resource_limit_reached", "scan_error":
			issues = append(issues, entry)
		default:
			diagnostics = append(diagnostics, entry)
		}
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf(`<p class="coverage-counts">%d execution issues · %d additional diagnostic records</p>`, len(issues), len(diagnostics)))
	if len(issues) > 0 {
		b.WriteString(coverageTableHTML(issues))
	}
	if len(diagnostics) > 0 {
		b.WriteString(fmt.Sprintf(`<details class="technical-details"><summary>Skipped checks, verification and probe details (%d)</summary>`, len(diagnostics)))
		b.WriteString(coverageTableHTML(diagnostics))
		b.WriteString(`</details>`)
	}
	return b.String()
}

func scrollTableHTML(table string) string {
	return `<div class="table-scroll" tabindex="0" role="region" aria-label="Report table">` + table + `</div>`
}

func coverageTableHTML(entries []CoverageEntry) string {
	var b strings.Builder
	b.WriteString(`<table class="data"><thead><tr><th>Type</th><th>Module / Phase</th><th>Summary</th><th>Endpoint</th><th>Decision</th></tr></thead><tbody>`)
	for _, entry := range entries {
		owner := entry.Module
		if owner == "" {
			owner = entry.Phase
		}
		decision := entry.Reason
		if decision == "" && len(entry.Reasons) > 0 {
			decision = strings.Join(entry.Reasons, ", ")
		}
		if entry.ProofType != "" {
			if decision != "" {
				decision += " · "
			}
			decision += "proof=" + entry.ProofType
		}
		if entry.Confidence != "" {
			decision += fmt.Sprintf(" · confidence=%s (%.2f)", entry.Confidence, entry.Score)
		}
		b.WriteString(`<tr><td>` + template.HTMLEscapeString(entry.EventType) + `</td><td>` +
			template.HTMLEscapeString(owner) + `</td><td>` + template.HTMLEscapeString(entry.Summary) +
			`</td><td><code>` + template.HTMLEscapeString(entry.Endpoint) + `</code></td><td>` +
			template.HTMLEscapeString(decision) + `</td></tr>`)
	}
	b.WriteString(`</tbody></table>`)
	return scrollTableHTML(b.String())
}

func manualLeadsHTML(entries []ManualLeadEntry, kind TemplateKind) string {
	if len(entries) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<div class="card"><p><strong>` + fmt.Sprintf("%d", len(entries)) +
		` passive or manually reviewable finding(s).</strong> These records are preserved in the comprehensive report, but must not be submitted as bug-bounty findings without manual proof.</p></div>`)
	for _, entry := range entries {
		b.WriteString(`<div class="card"><p><strong>Manual-review warning:</strong> ` +
			template.HTMLEscapeString(entry.Warning) + `</p></div>`)
		b.WriteString(findingHTML(entry.Finding, kind))
	}
	return b.String()
}

func highlightEvidence(escaped string, markers []string) string {
	needles := append([]string{}, markers...)
	seen := map[string]struct{}{}
	// Find ranges in the original escaped text. Never search generated markup:
	// overlapping markers such as "secret", "span" or "class" can corrupt it.
	sorted := make([]string, 0, len(needles))
	for _, needle := range needles {
		needle = strings.TrimSpace(needle)
		if needle == "" {
			continue
		}
		if _, ok := seen[strings.ToLower(needle)]; ok {
			continue
		}
		seen[strings.ToLower(needle)] = struct{}{}
		sorted = append(sorted, needle)
	}
	sort.Slice(sorted, func(i, j int) bool { return len(sorted[i]) > len(sorted[j]) })
	type matchRange struct{ start, end int }
	var matches []matchRange
	for _, needle := range sorted {
		escNeedle := template.HTMLEscapeString(needle)
		if escNeedle == "" {
			continue
		}
		re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(escNeedle))
		for _, hit := range re.FindAllStringIndex(escaped, 2000) {
			overlaps := false
			for _, existing := range matches {
				if hit[0] < existing.end && hit[1] > existing.start {
					overlaps = true
					break
				}
			}
			if !overlaps {
				matches = append(matches, matchRange{hit[0], hit[1]})
			}
			if len(matches) >= 2000 {
				break
			}
		}
		if len(matches) >= 2000 {
			break
		}
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].start < matches[j].start })
	var out strings.Builder
	position := 0
	for _, hit := range matches {
		out.WriteString(escaped[position:hit.start])
		out.WriteString(`<span class="vuln-hit">`)
		out.WriteString(escaped[hit.start:hit.end])
		out.WriteString(`</span>`)
		position = hit.end
	}
	out.WriteString(escaped[position:])
	return out.String()
}

func findingMarkdown(f FindingEntry) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("## [%s] %s\n\n", strings.ToUpper(f.Severity), f.Title))
	b.WriteString(fmt.Sprintf("- **Vulnerability Class:** `%s`\n", f.VulnClass))
	if len(f.CWE) > 0 {
		b.WriteString(fmt.Sprintf("- **CWE:** `%s`\n", strings.Join(f.CWE, "`, `")))
	}
	if len(f.OWASPTop102025) > 0 {
		b.WriteString(fmt.Sprintf("- **OWASP Top 10:2025:** %s\n", strings.Join(f.OWASPTop102025, ", ")))
	}
	b.WriteString(fmt.Sprintf("- **Confidence:** %s\n", f.ConfidenceExplain))
	if f.EndpointURL != "" {
		b.WriteString(fmt.Sprintf("- **Vulnerable URL:** `%s`\n", f.EndpointURL))
	}
	if f.Parameter != "" {
		b.WriteString(fmt.Sprintf("- **Vulnerable Parameter:** `%s`\n", f.Parameter))
	}
	if f.HTTPEvidence.Signal != "" {
		b.WriteString(fmt.Sprintf("- **Verification Signal:** `%s`\n", f.HTTPEvidence.Signal))
	}

	b.WriteString("\n### Summary\n\n" + f.Description + "\n\n")

	b.WriteString("### Steps To Reproduce\n\n")
	if f.HTTPEvidence.CurlCommand != "" {
		b.WriteString("Run the following cURL command to reproduce the vulnerability:\n\n```bash\n" + f.HTTPEvidence.CurlCommand + "\n```\n\n")
	} else if f.HTTPEvidence.Payload != "" {
		b.WriteString(fmt.Sprintf("1. Send a request to `%s`.\n2. Inject the payload `%s` into parameter `%s`.\n3. Observe the confirmed response.\n\n", f.EndpointURL, f.HTTPEvidence.Payload, f.Parameter))
	} else {
		b.WriteString(fmt.Sprintf("1. Navigate to `%s`.\n2. Observe the security finding.\n\n", f.EndpointURL))
	}

	if f.HTTPEvidence.Payload != "" {
		b.WriteString("### Applied Payload\n\n```\n" + f.HTTPEvidence.Payload + "\n```\n\n")
	}
	if f.HTTPEvidence.RawRequest != "" {
		b.WriteString("### HTTP Request Proof\n\n```http\n" + f.HTTPEvidence.RawRequest + "\n```\n\n")
	}
	if f.HTTPEvidence.RawResponse != "" {
		b.WriteString("### HTTP Response Proof\n\n```http\n" + f.HTTPEvidence.RawResponse + "\n```\n\n")
	}

	b.WriteString("### Impact\n\n" + f.Impact + "\n\n")
	b.WriteString("### Remediation\n\n" + f.Remediation + "\n\n")
	b.WriteString("---\n\n")
	return b.String()
}
