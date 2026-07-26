package report

import (
	"fmt"
	"html/template"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/akha-security/akca/engine/internal/evidencemarkers"
	"github.com/akha-security/akca/engine/internal/storage"
)

func htmlDocStart(meta Document) string {
	critCount := meta.Metrics.BySeverity["critical"]
	highCount := meta.Metrics.BySeverity["high"]
	medCount := meta.Metrics.BySeverity["medium"]
	lowCount := meta.Metrics.BySeverity["low"]
	infoCount := meta.Metrics.BySeverity["info"]

	riskLabel := "Secure / Info"
	riskClass := "risk-info"
	if critCount > 0 {
		riskLabel = "Critical Risk"
		riskClass = "risk-critical"
	} else if highCount > 0 {
		riskLabel = "High Risk"
		riskClass = "risk-high"
	} else if medCount > 0 {
		riskLabel = "Medium Risk"
		riskClass = "risk-medium"
	} else if lowCount > 0 {
		riskLabel = "Low Risk"
		riskClass = "risk-low"
	}

	targetsStr := "Unknown"
	if len(meta.Scope.Targets) > 0 {
		targetsStr = strings.Join(meta.Scope.Targets, ", ")
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Outfit:wght@400;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');
:root {
	--bg: #090d16;
	--card: #101626;
	--card-hover: #162035;
	--ink: #f1f5f9;
	--muted: #94a3b8;
	--line: #1e293b;
	--accent: #06b6d4;
	--crit: #ef4444;
	--crit-bg: rgba(239,68,68,0.1);
	--crit-glow: rgba(239,68,68,0.25);
	--high: #f97316;
	--high-bg: rgba(249,115,22,0.1);
	--high-glow: rgba(249,115,22,0.25);
	--med: #f59e0b;
	--med-bg: rgba(245,158,11,0.1);
	--med-glow: rgba(245,158,11,0.25);
	--low: #10b981;
	--low-bg: rgba(16,185,129,0.1);
	--low-glow: rgba(16,185,129,0.25);
	--info: #3b82f6;
	--info-bg: rgba(59,130,246,0.1);
	--info-glow: rgba(59,130,246,0.25);
}
* { box-sizing: border-box; }
body {
	margin: 0;
	font-family: 'Inter', system-ui, -apple-system, sans-serif;
	background: var(--bg);
	color: var(--ink);
	line-height: 1.6;
}
.wrap {
	max-width: 1600px;
	margin: 0 auto;
	padding: 2.5rem 2.5rem 4rem;
}
.report-hero {
	background: linear-gradient(135deg, #1e1b4b 0%%, #0f172a 60%%, #082f49 100%%);
	border: 1px solid var(--line);
	color: #fff;
	border-radius: 16px;
	padding: 2.25rem 2.5rem;
	margin-bottom: 2rem;
	box-shadow: 0 10px 40px rgba(0, 0, 0, 0.4);
	position: relative;
	overflow: hidden;
}
.report-hero::before {
	content: '';
	position: absolute;
	top: 0; left: 0; right: 0; bottom: 0;
	background: radial-gradient(circle at top right, rgba(6,182,212,0.15), transparent 60%%);
	pointer-events: none;
}
.hero-flex {
	display: flex;
	justify-content: space-between;
	align-items: center;
	flex-wrap: wrap;
	gap: 1rem;
	position: relative;
	z-index: 1;
}
.report-hero h1 {
	margin: 0 0 0.5rem;
	font-family: 'Outfit', sans-serif;
	font-size: 2.2rem;
	font-weight: 800;
	letter-spacing: -0.03em;
	background: linear-gradient(to right, #ffffff, #94a3b8);
	-webkit-background-clip: text;
	-webkit-text-fill-color: transparent;
}
.report-hero .sub {
	color: #94a3b8;
	font-size: 1rem;
	margin: 0;
	font-weight: 400;
}
.brand-tag {
	font-family: 'Outfit', sans-serif;
	font-size: 0.88rem;
	color: #64748b;
	text-transform: uppercase;
	letter-spacing: 0.1em;
	background: rgba(255,255,255,0.03);
	padding: 0.5rem 1rem;
	border-radius: 8px;
	border: 1px solid rgba(255,255,255,0.05);
}
.brand-tag span {
	color: var(--accent);
	font-weight: 700;
}
.report-grid {
	display: grid;
	grid-template-columns: 1.2fr 1fr 1.8fr;
	gap: 1.5rem;
	margin-bottom: 2rem;
}
@media (max-width: 1024px) {
	.report-grid {
		grid-template-columns: 1fr;
	}
}
.meta-card, .risk-card, .breakdown-card {
	display: flex;
	flex-direction: column;
	justify-content: space-between;
}
.meta-card h3, .risk-card h3, .breakdown-card h3 {
	margin: 0 0 1rem;
	font-family: 'Outfit', sans-serif;
	font-size: 0.9rem;
	font-weight: 700;
	color: #64748b;
	text-transform: uppercase;
	letter-spacing: 0.05em;
}
.meta-table {
	width: 100%%;
	border-collapse: collapse;
	font-size: 0.85rem;
}
.meta-table td {
	padding: 0.4rem 0;
	color: #cbd5e1;
}
.meta-table td:first-child {
	color: var(--muted);
	width: 30%%;
	font-weight: 500;
}
.meta-table code {
	background: rgba(255,255,255,0.05);
	padding: 0.1rem 0.4rem;
	border-radius: 4px;
	font-size: 0.78rem;
}
.risk-card {
	text-align: center;
	align-items: center;
}
.risk-gauge {
	font-family: 'Outfit', sans-serif;
	font-size: 1.4rem;
	font-weight: 800;
	padding: 0.6rem 1.5rem;
	border-radius: 12px;
	text-transform: uppercase;
	letter-spacing: 0.05em;
	display: inline-block;
	margin: 0.5rem 0;
	box-shadow: 0 0 25px var(--glow);
}
.risk-desc {
	margin: 0.5rem 0 0;
	font-size: 0.74rem;
	color: var(--muted);
}
.risk-critical { --glow: rgba(239,68,68,0.25); }
.risk-high { --glow: rgba(249,115,22,0.25); }
.risk-medium { --glow: rgba(245,158,11,0.25); }
.risk-low { --glow: rgba(16,185,129,0.25); }
.risk-info { --glow: rgba(59,130,246,0.25); }
.risk-card.risk-critical .risk-gauge { background: var(--crit-bg); color: var(--crit); border: 1px solid var(--crit); }
.risk-card.risk-high .risk-gauge { background: var(--high-bg); color: var(--high); border: 1px solid var(--high); }
.risk-card.risk-medium .risk-gauge { background: var(--med-bg); color: var(--med); border: 1px solid var(--med); }
.risk-card.risk-low .risk-gauge { background: var(--low-bg); color: var(--low); border: 1px solid var(--low); }
.risk-card.risk-info .risk-gauge { background: var(--info-bg); color: var(--info); border: 1px solid var(--info); }
.breakdown-grid {
	display: grid;
	grid-template-columns: repeat(5, 1fr);
	gap: 0.75rem;
	width: 100%%;
}
.b-box {
	display: flex;
	flex-direction: column;
	align-items: center;
	justify-content: center;
	padding: 0.85rem 0.5rem;
	border-radius: 12px;
	border: 1px solid var(--line);
	background: rgba(255,255,255,0.01);
	transition: all 0.2s;
}
.b-box:hover {
	background: rgba(255,255,255,0.02);
}
.b-box .cnt {
	font-family: 'Outfit', sans-serif;
	font-size: 1.6rem;
	font-weight: 800;
	line-height: 1.2;
}
.b-box .lbl {
	font-size: 0.68rem;
	color: var(--muted);
	font-weight: 600;
	text-transform: uppercase;
	letter-spacing: 0.05em;
	margin-top: 0.25rem;
}
.b-box.crit .cnt { color: var(--crit); }
.b-box.high .cnt { color: var(--high); }
.b-box.med .cnt { color: var(--med); }
.b-box.low .cnt { color: var(--low); }
.b-box.info .cnt { color: var(--info); }
section.report-section {
	margin-bottom: 2.5rem;
}
section.report-section > h2 {
	font-family: 'Outfit', sans-serif;
	font-size: 1.35rem;
	font-weight: 700;
	margin: 0 0 1rem;
	padding-bottom: 0.5rem;
	border-bottom: 1px solid var(--line);
	color: #cbd5e1;
	letter-spacing: -0.01em;
}
.card {
	background: var(--card);
	border: 1px solid var(--line);
	border-radius: 16px;
	padding: 1.5rem;
	box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
}
.metrics {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
	gap: 1rem;
}
.metric {
	background: var(--card);
	border: 1px solid var(--line);
	border-radius: 14px;
	padding: 1.25rem;
	text-align: center;
	transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
	box-shadow: 0 4px 12px rgba(0,0,0,0.15);
}
.metric:hover {
	transform: translateY(-2px);
	border-color: var(--accent);
	box-shadow: 0 8px 24px rgba(6,182,212,0.1);
}
.metric .n {
	font-family: 'Outfit', sans-serif;
	font-size: 2rem;
	font-weight: 800;
	color: var(--accent);
	line-height: 1.2;
}
.metric .l {
	font-size: 0.76rem;
	color: var(--muted);
	text-transform: uppercase;
	letter-spacing: 0.06em;
	font-weight: 600;
	margin-top: 0.25rem;
}
.findings-list {
	display: flex;
	flex-direction: column;
	gap: 1.25rem;
}
.finding {
	background: var(--card);
	border: 1px solid var(--line);
	border-radius: 16px;
	padding: 1.75rem 2rem;
	box-shadow: 0 4px 25px rgba(0, 0, 0, 0.25);
	transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
	position: relative;
	overflow: hidden;
}
.finding:hover {
	transform: translateY(-2px);
	box-shadow: 0 10px 35px rgba(0, 0, 0, 0.35);
	border-color: #334155;
}
.finding h3 {
	margin: 0 0 0.75rem;
	font-family: 'Outfit', sans-serif;
	font-size: 1.25rem;
	font-weight: 700;
	color: #fff;
	letter-spacing: -0.01em;
}
.finding.sev-critical { border-left: 6px solid var(--crit); }
.finding.sev-high { border-left: 6px solid var(--high); }
.finding.sev-medium { border-left: 6px solid var(--med); }
.finding.sev-low { border-left: 6px solid var(--low); }
.finding.sev-info { border-left: 6px solid var(--info); }
.finding.sev-critical:hover { border-color: var(--crit); }
.finding.sev-high:hover { border-color: var(--high); }
.finding.sev-medium:hover { border-color: var(--med); }
.finding.sev-low:hover { border-color: var(--low); }
.finding.sev-info:hover { border-color: var(--info); }
.badge {
	display: inline-block;
	padding: 0.2rem 0.75rem;
	border-radius: 99px;
	font-size: 0.7rem;
	font-weight: 800;
	text-transform: uppercase;
	letter-spacing: 0.05em;
	margin-right: 0.75rem;
	border: 1px solid transparent;
}
.badge-critical { background: var(--crit-bg); color: var(--crit); border-color: rgba(239,68,68,0.2); }
.badge-high { background: var(--high-bg); color: var(--high); border-color: rgba(249,115,22,0.2); }
.badge-medium { background: var(--med-bg); color: var(--med); border-color: rgba(245,158,11,0.2); }
.badge-low { background: var(--low-bg); color: var(--low); border-color: rgba(16,185,129,0.2); }
.badge-info { background: var(--info-bg); color: var(--info); border-color: rgba(59,130,246,0.2); }
.meta-line {
	color: var(--muted);
	font-size: 0.88rem;
	margin-bottom: 1rem;
	display: flex;
	align-items: center;
	flex-wrap: wrap;
	gap: 0.5rem;
}
.meta-line code {
	background: rgba(255,255,255,0.04);
	padding: 0.1rem 0.4rem;
	border-radius: 4px;
	border: 1px solid rgba(255,255,255,0.06);
	font-size: 0.8rem;
	color: #e2e8f0;
}
.kv {
	display: grid;
	grid-template-columns: 8rem 1fr;
	gap: 0.5rem 1rem;
	font-size: 0.88rem;
	margin: 1.25rem 0;
	background: rgba(255,255,255,0.01);
	padding: 1rem;
	border-radius: 12px;
	border: 1px solid rgba(255,255,255,0.03);
}
.kv dt {
	color: var(--muted);
	font-weight: 600;
}
.kv dd {
	margin: 0;
	color: #e2e8f0;
	word-break: break-all;
	font-family: monospace;
}
h4 {
	margin: 1.5rem 0 0.5rem;
	font-family: 'Outfit', sans-serif;
	font-size: 0.95rem;
	font-weight: 700;
	color: #94a3b8;
	text-transform: uppercase;
	letter-spacing: 0.05em;
}
pre.http {
	background: #05070c;
	color: #cbd5e1;
	font-family: 'JetBrains Mono', Consolas, monospace;
	border-radius: 10px;
	padding: 1.25rem;
	overflow-x: auto;
	font-size: 0.8rem;
	line-height: 1.6;
	white-space: pre-wrap;
	word-break: break-all;
	border: 1px solid #111827;
	margin: 0;
}
.vuln-hit {
	background: rgba(239, 68, 68, 0.25);
	color: #fca5a5;
	padding: 2px 6px;
	border-radius: 4px;
	font-weight: 600;
	border: 1px solid rgba(239, 68, 68, 0.4);
	text-shadow: 0 0 8px rgba(239, 68, 68, 0.6);
}
details {
	margin-bottom: 1rem;
	border: 1px solid var(--line);
	border-radius: 10px;
	background: #0b0f19;
	overflow: hidden;
	transition: border-color 0.2s;
}
details[open] {
	border-color: #334155;
}
summary {
	padding: 0.85rem 1.25rem;
	font-weight: 600;
	font-size: 0.86rem;
	cursor: pointer;
	user-select: none;
	background: #0d1322;
	outline: none;
	color: #cbd5e1;
	transition: background 0.2s;
}
summary:hover {
	background: #162035;
}
details[open] summary {
	border-bottom: 1px solid var(--line);
	background: #111827;
}
.payload-box {
	background: #05070c;
	border: 1px solid #111827;
	border-radius: 8px;
	padding: 0.85rem 1.25rem;
	font-family: 'JetBrains Mono', monospace;
	font-size: 0.82rem;
	color: #e2e8f0;
	word-break: break-all;
}
table.data {
	width: 100%%;
	border-collapse: collapse;
	font-size: 0.88rem;
	background: var(--card);
	border-radius: 12px;
	overflow: hidden;
	border: 1px solid var(--line);
}
table.data th, table.data td {
	padding: 0.85rem 1rem;
	text-align: left;
	border-bottom: 1px solid var(--line);
}
table.data th {
	background: #0f172a;
	font-weight: 600;
	color: #cbd5e1;
	border-bottom: 2px solid var(--line);
}
table.data tr:last-child td {
	border-bottom: none;
}
ul.scope {
	list-style: none;
	padding: 0;
	margin: 0 0 1rem;
}
ul.scope li {
	padding: 0.5rem 0.75rem;
	background: rgba(255,255,255,0.02);
	border: 1px solid var(--line);
	border-radius: 8px;
	margin-bottom: 0.5rem;
	font-family: monospace;
	color: #e2e8f0;
}
.filter-controls {
	display: flex;
	flex-wrap: wrap;
	justify-content: space-between;
	align-items: center;
	gap: 1rem;
	margin-bottom: 1.5rem;
	background: #0f172a;
	padding: 1rem 1.25rem;
	border-radius: 12px;
	border: 1px solid var(--line);
}
.filter-controls input[type="text"] {
	background: #090d16;
	border: 1px solid var(--line);
	color: #fff;
	padding: 0.55rem 1rem;
	border-radius: 8px;
	font-size: 0.86rem;
	width: 100%%;
	max-width: 320px;
	outline: none;
	transition: border-color 0.2s;
}
.filter-controls input[type="text"]:focus {
	border-color: var(--accent);
}
.filter-buttons {
	display: flex;
	gap: 0.5rem;
	flex-wrap: wrap;
}
.filter-btn {
	background: transparent;
	border: 1px solid var(--line);
	color: var(--muted);
	padding: 0.45rem 1rem;
	border-radius: 8px;
	font-size: 0.84rem;
	font-weight: 600;
	cursor: pointer;
	transition: all 0.2s;
}
.filter-btn:hover {
	background: rgba(255,255,255,0.03);
	color: #fff;
}
.filter-btn.active {
	background: var(--accent);
	border-color: var(--accent);
	color: #090d16;
}
.filter-btn[data-sev="critical"].active { background: var(--crit); color: #fff; border-color: var(--crit); }
.filter-btn[data-sev="high"].active { background: var(--high); color: #fff; border-color: var(--high); }
.filter-btn[data-sev="medium"].active { background: var(--med); color: #090d16; border-color: var(--med); }
.filter-btn[data-sev="low"].active { background: var(--low); color: #fff; border-color: var(--low); }
@media print{body{background:#fff}.wrap{padding:0}.report-hero{box-shadow:none}}
</style></head><body><div class="wrap">
<header class="report-hero">
  <div class="hero-flex">
    <div>
      <h1>%s</h1>
      <p class="sub">%s</p>
    </div>
    <div class="brand-tag">Powered by <span>Akca Security</span></div>
  </div>
</header>
<div class="report-grid">
  <div class="card meta-card">
    <h3>Scan Information</h3>
    <table class="meta-table">
      <tr><td>Target:</td><td><strong>%s</strong></td></tr>
      <tr><td>Scan ID:</td><td><code>%s</code></td></tr>
      <tr><td>Generated:</td><td>%s</td></tr>
      <tr><td>Scope:</td><td>%d targets</td></tr>
    </table>
  </div>
  <div class="card risk-card %s">
    <h3>Overall Risk Level</h3>
    <div class="risk-gauge">%s</div>
    <p class="risk-desc">Highest severity vulnerability determines the overall target risk level.</p>
  </div>
  <div class="card breakdown-card">
    <h3>Vulnerabilities Found</h3>
    <div class="breakdown-grid">
      <div class="b-box crit">
        <span class="cnt">%d</span>
        <span class="lbl">Critical</span>
      </div>
      <div class="b-box high">
        <span class="cnt">%d</span>
        <span class="lbl">High</span>
      </div>
      <div class="b-box med">
        <span class="cnt">%d</span>
        <span class="lbl">Medium</span>
      </div>
      <div class="b-box low">
        <span class="cnt">%d</span>
        <span class="lbl">Low</span>
      </div>
      <div class="b-box info">
        <span class="cnt">%d</span>
        <span class="lbl">Info</span>
      </div>
    </div>
  </div>
</div>`,
		template.HTMLEscapeString(meta.Title),
		template.HTMLEscapeString(meta.Title),
		template.HTMLEscapeString(meta.Summary),
		template.HTMLEscapeString(targetsStr),
		template.HTMLEscapeString(meta.Scope.ScanID),
		meta.GeneratedAt.Format("2006-01-02 15:04 UTC"),
		len(meta.Scope.Targets),
		riskClass,
		riskLabel,
		critCount,
		highCount,
		medCount,
		lowCount,
		infoCount,
	)
}

func htmlDocEnd() string {
	return `</div>
<script>
let activeSeverity = 'all';

function setSeverityFilter(sev, btn) {
    activeSeverity = sev;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    applyFilters();
}

function applyFilters() {
    const q = document.getElementById('vulnSearch').value.toLowerCase();
    document.querySelectorAll('.finding').forEach(card => {
        const title = card.querySelector('h3').textContent.toLowerCase();
        const vulnClass = card.getAttribute('data-class').toLowerCase();
        const severity = card.getAttribute('data-severity').toLowerCase();
        
        const matchesQuery = title.includes(q) || vulnClass.includes(q);
        const matchesSeverity = activeSeverity === 'all' || severity === activeSeverity;
        
        if (matchesQuery && matchesSeverity) {
            card.style.display = 'block';
        } else {
            card.style.display = 'none';
        }
    });
}
</script>
</body></html>`
}

func renderHTMLSection(w io.Writer, id, title, body string) error {
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
<div class="metric"><div class="n">%d</div><div class="l">Evidence</div></div>
<div class="metric"><div class="n">%d</div><div class="l">Endpoints</div></div>
<div class="metric"><div class="n">%d</div><div class="l">OAST</div></div>
</div>`,
		m.TotalFindings, m.EvidenceCount, m.EndpointCount, m.OASTCallbacks)
}

func apiKeysHTML(keys []APIKeySection) string {
	if len(keys) == 0 {
		return "<p class=\"meta-line\">No API key validation results recorded.</p>"
	}
	var b strings.Builder
	b.WriteString("<table class=\"data\"><tr><th>Service</th><th>Status</th><th>Risk</th><th>Remediation</th></tr>")
	for _, k := range keys {
		b.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
			template.HTMLEscapeString(k.Service),
			template.HTMLEscapeString(k.Status),
			template.HTMLEscapeString(k.Risk),
			template.HTMLEscapeString(k.Remediation)))
	}
	b.WriteString("</table>")
	return b.String()
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
	b.WriteString("<h3>" + template.HTMLEscapeString(f.Title) + "</h3>")
	b.WriteString(`<p class="meta-line"><span class="badge badge-` + template.HTMLEscapeString(sevKey) + `">` +
		template.HTMLEscapeString(f.Severity) + `</span>`)
	b.WriteString(`Confidence: ` + template.HTMLEscapeString(f.Confidence) +
		` · Class: <code>` + template.HTMLEscapeString(f.VulnClass) + `</code></p>`)

	switch kind {
	case TemplateHackerOne:
		b.WriteString("<h4>Weakness</h4><p>" + template.HTMLEscapeString(f.Description) + "</p>")
		b.WriteString("<h4>Steps to Reproduce</h4><ol>")
		for _, s := range f.ReproductionSteps {
			b.WriteString("<li>" + template.HTMLEscapeString(s) + "</li>")
		}
		b.WriteString("</ol>")
	case TemplateBugcrowd:
		b.WriteString("<h4>Description</h4><p>" + template.HTMLEscapeString(f.Description) + "</p>")
		b.WriteString("<h4>Proof of Concept</h4>")
	default:
		b.WriteString("<h4>Description</h4><p>" + template.HTMLEscapeString(f.Description) + "</p>")
	}

	b.WriteString(findingMetaHTML(f))
	b.WriteString("<h4>Impact</h4><p>" + template.HTMLEscapeString(f.Impact) + "</p>")
	if kind != TemplateHackerOne {
		b.WriteString("<h4>Remediation</h4><p>" + template.HTMLEscapeString(f.Remediation) + "</p>")
	}
	b.WriteString(httpEvidenceHTML(f.HTTPEvidence))
	b.WriteString("<p class=\"meta-line\"><em>" + template.HTMLEscapeString(f.ConfidenceExplain) + "</em></p>")
	b.WriteString("</article>")
	return b.String()
}

func findingMetaHTML(f FindingEntry) string {
	var b strings.Builder
	b.WriteString(`<dl class="kv">`)
	if f.EndpointURL != "" {
		b.WriteString(`<dt>URL</dt><dd><code>` + template.HTMLEscapeString(f.EndpointURL) + `</code></dd>`)
	}
	if f.Parameter != "" {
		b.WriteString(`<dt>Parameter</dt><dd><strong>` + template.HTMLEscapeString(f.Parameter) + `</strong></dd>`)
	}
	if f.HTTPEvidence.Location != "" {
		b.WriteString(`<dt>Location</dt><dd>` + template.HTMLEscapeString(f.HTTPEvidence.Location) + `</dd>`)
	}
	if f.HTTPEvidence.Method != "" || f.HTTPEvidence.URL != "" {
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
	if ev.RawRequest == "" && ev.RawResponse == "" && ev.CurlCommand == "" && ev.Payload == "" {
		return ""
	}
	markers := evidencemarkers.ForReport(ev.Payload, ev.Signal, ev.RespBody, ev.ResponseMarkers)
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
	if len(ev.Observations) > 0 {
		b.WriteString(`<p><strong>Evidence ledger</strong>: ` +
			fmt.Sprintf("%d baseline, %d probe, %d control, %d replay, %d state, %d identity, %d external",
				len(ev.Baseline), len(ev.Probes), len(ev.Controls), len(ev.Replays),
				len(ev.State), len(ev.Identity), len(ev.ExternalProof)) + `</p>`)
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
	if ev.ScreenshotRef != "" {
		b.WriteString(`<p><strong>Browser screenshot</strong>: <code>` +
			template.HTMLEscapeString(ev.ScreenshotRef) + `</code></p>`)
	}
	if ev.DOMSnapshotRef != "" {
		b.WriteString(`<p><strong>DOM snapshot</strong>: <code>` +
			template.HTMLEscapeString(ev.DOMSnapshotRef) + `</code></p>`)
	}
	if ev.RawRequest != "" {
		b.WriteString(`<details><summary>▼ Show Raw HTTP Request</summary><pre class="http">` +
			highlightEvidence(template.HTMLEscapeString(ev.RawRequest), []string{ev.Payload}) + `</pre></details>`)
	}
	if ev.RawResponse != "" {
		b.WriteString(`<details><summary>▼ Show Raw HTTP Response (proof highlighted)</summary><pre class="http">` +
			highlightEvidence(template.HTMLEscapeString(ev.RawResponse), markers) + `</pre></details>`)
	}
	if ev.CurlCommand != "" {
		b.WriteString(`<details><summary>▼ Show cURL Command</summary><pre class="http">` + template.HTMLEscapeString(ev.CurlCommand) + `</pre></details>`)
	}
	return b.String()
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
	for _, entry := range entries {
		b.WriteString(`<div class="card"><p><strong>` + template.HTMLEscapeString(entry.Method+" "+entry.URL) + `</strong> — ` + fmt.Sprintf("%d", entry.StatusCode) + `</p>`)
		b.WriteString(`<details><summary>Show Raw HTTP Request</summary><pre class="http">` + template.HTMLEscapeString(entry.RawRequest) + `</pre></details>`)
		b.WriteString(`<details><summary>Show Raw HTTP Response</summary><pre class="http">` + template.HTMLEscapeString(entry.RawResponse) + `</pre></details></div>`)
	}
	return b.String()
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
	out := escaped
	needles := append([]string{}, markers...)
	seen := map[string]struct{}{}
	// Longest needles first so shorter matches do not break longer ones.
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
	for _, needle := range sorted {
		escNeedle := template.HTMLEscapeString(needle)
		if escNeedle == "" {
			continue
		}
		if strings.Contains(out, escNeedle) {
			out = strings.ReplaceAll(out, escNeedle, `<span class="vuln-hit">`+escNeedle+`</span>`)
			continue
		}
		re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(escNeedle))
		out = re.ReplaceAllStringFunc(out, func(hit string) string {
			return `<span class="vuln-hit">` + hit + `</span>`
		})
	}
	return out
}

func findingMarkdown(f FindingEntry) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("### [%s] %s\n\n", f.Severity, f.Title))
	b.WriteString(fmt.Sprintf("- **Confidence:** %s\n", f.ConfidenceExplain))
	if f.EndpointURL != "" {
		b.WriteString(fmt.Sprintf("- **URL:** `%s`\n", f.EndpointURL))
	}
	if f.Parameter != "" {
		b.WriteString(fmt.Sprintf("- **Parameter:** `%s`\n", f.Parameter))
	}
	if f.HTTPEvidence.Signal != "" {
		b.WriteString(fmt.Sprintf("- **Signal:** `%s`\n", f.HTTPEvidence.Signal))
	}
	b.WriteString("\n**Description**\n\n" + f.Description + "\n\n")
	b.WriteString("**Impact**\n\n" + f.Impact + "\n\n")
	b.WriteString("**Remediation**\n\n" + f.Remediation + "\n\n")
	if f.HTTPEvidence.Payload != "" {
		b.WriteString("**Applied payload**\n\n```\n" + f.HTTPEvidence.Payload + "\n```\n\n")
	}
	if f.HTTPEvidence.RawRequest != "" {
		b.WriteString("**Request**\n\n```http\n" + f.HTTPEvidence.RawRequest + "\n```\n\n")
	}
	if f.HTTPEvidence.RawResponse != "" {
		b.WriteString("**Response**\n\n```http\n" + f.HTTPEvidence.RawResponse + "\n```\n\n")
	}
	if f.HTTPEvidence.CurlCommand != "" {
		b.WriteString("**cURL**\n\n```bash\n" + f.HTTPEvidence.CurlCommand + "\n```\n\n")
	}
	return b.String()
}
