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
	b.WriteString(`<section id="overview" class="vulnerability-overview">`)
	b.WriteString(`<div class="section-heading"><div><span class="eyebrow">Attack surface overview</span><h2>Vulnerabilities at a glance</h2><p>Confirmed and high-confidence findings grouped by vulnerability type.</p></div>`)
	b.WriteString(`<button type="button" class="text-action" onclick="setClassFilter('all')">View all findings →</button></div>`)
	if len(items) == 0 {
		b.WriteString(`<div class="empty-state"><strong>No reportable vulnerabilities found.</strong><span>The assessment did not produce a confirmed or high-confidence finding.</span></div>`)
	} else {
		b.WriteString(`<div class="vulnerability-grid">`)
		for index, item := range items {
			b.WriteString(`<button type="button" class="vulnerability-tile" data-vclass="` +
				template.HTMLEscapeString(item.Class) + `" onclick="setClassFilter(this.dataset.vclass)">`)
			b.WriteString(`<span class="tile-rank">` + fmt.Sprintf("%02d", index+1) + `</span>`)
			b.WriteString(`<span class="tile-copy"><strong>` + template.HTMLEscapeString(item.Label) +
				`</strong><small>` + template.HTMLEscapeString(item.Class) + `</small></span>`)
			b.WriteString(`<span class="tile-count">` + fmt.Sprintf("%d", item.Count) + `</span></button>`)
		}
		b.WriteString(`</div>`)
	}
	b.WriteString(`</section>`)
	return b.String()
}

func htmlDocStart(meta Document) string {
	critCount := meta.Metrics.BySeverity["critical"]
	highCount := meta.Metrics.BySeverity["high"]
	medCount := meta.Metrics.BySeverity["medium"]
	lowCount := meta.Metrics.BySeverity["low"]
	infoCount := meta.Metrics.BySeverity["info"]

	riskLabel := "Secure / Low Risk"
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
	startedStr := meta.Metrics.StartedAt
	if startedStr == "" {
		startedStr = meta.GeneratedAt.Format("2006-01-02 15:04:05 UTC")
	}
	finishedStr := meta.Metrics.FinishedAt
	if finishedStr == "" {
		finishedStr = meta.GeneratedAt.Format("2006-01-02 15:04:05 UTC")
	}
	durationStr := meta.Metrics.Duration
	if durationStr == "" {
		durationStr = "< 1s"
	}
	totalReqs := meta.Metrics.TotalRequests

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en" data-theme="light"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root {
	/* Light Mode Variables (Default) */
	--bg: #f8fafc;
	--bg-subtle: #f1f5f9;
	--card: #ffffff;
	--card-hover: #fcfdfe;
	--ink: #0f172a;
	--ink-heading: #020617;
	--muted: #64748b;
	--line: #e2e8f0;
	--line-subtle: #f1f5f9;
	--accent: #0284c7;
	--accent-hover: #0369a1;
	--accent-soft: rgba(2, 132, 199, 0.08);
	--crit: #dc2626;
	--crit-bg: #fef2f2;
	--crit-border: #fecaca;
	--crit-ink: #991b1b;
	--high: #ea580c;
	--high-bg: #fff7ed;
	--high-border: #fed7aa;
	--high-ink: #9a3412;
	--med: #d97706;
	--med-bg: #fffbeb;
	--med-border: #fde68a;
	--med-ink: #92400e;
	--low: #16a34a;
	--low-bg: #f0fdf4;
	--low-border: #bbf7d0;
	--low-ink: #166534;
	--info: #2563eb;
	--info-bg: #eff6ff;
	--info-border: #bfdbfe;
	--info-ink: #1e40af;
	--panel: #f8fafc;
	--panel-soft: #f1f5f9;
	--code-bg: #f1f5f9;
	--code-ink: #0f172a;
	--http-bg: #0f172a;
	--http-ink: #f8fafc;
	--http-border: #1e293b;
	--http-header-bg: #1e293b;
	--shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
	--shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.07), 0 2px 4px -2px rgba(0, 0, 0, 0.05);
	--shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.08), 0 4px 6px -4px rgba(0, 0, 0, 0.04);
	--glow: rgba(0, 0, 0, 0.06);
	--radius: 12px;
	--radius-lg: 16px;
}

html[data-theme="dark"] {
	/* Dark Mode Variables */
	--bg: #090d16;
	--bg-subtle: #0d1322;
	--card: #101626;
	--card-hover: #162035;
	--ink: #f1f5f9;
	--ink-heading: #ffffff;
	--muted: #94a3b8;
	--line: #1e293b;
	--line-subtle: #162035;
	--accent: #22d3ee;
	--accent-hover: #67e8f9;
	--accent-soft: rgba(34, 211, 238, 0.12);
	--crit: #ef4444;
	--crit-bg: rgba(239, 68, 68, 0.15);
	--crit-border: rgba(239, 68, 68, 0.3);
	--crit-ink: #fca5a5;
	--high: #f97316;
	--high-bg: rgba(249, 115, 22, 0.15);
	--high-border: rgba(249, 115, 22, 0.3);
	--high-ink: #fdba74;
	--med: #f59e0b;
	--med-bg: rgba(245, 158, 11, 0.15);
	--med-border: rgba(245, 158, 11, 0.3);
	--med-ink: #fde68a;
	--low: #10b981;
	--low-bg: rgba(16, 185, 129, 0.15);
	--low-border: rgba(16, 185, 129, 0.3);
	--low-ink: #86efac;
	--info: #3b82f6;
	--info-bg: rgba(59, 130, 246, 0.15);
	--info-border: rgba(59, 130, 246, 0.3);
	--info-ink: #93c5fd;
	--panel: #0d1322;
	--panel-soft: rgba(255, 255, 255, 0.02);
	--code-bg: #1e293b;
	--code-ink: #f1f5f9;
	--http-bg: #080c14;
	--http-ink: #f8fafc;
	--http-border: #1e293b;
	--http-header-bg: #0f172a;
	--shadow-sm: 0 1px 3px 0 rgba(0, 0, 0, 0.3);
	--shadow-md: 0 4px 12px 0 rgba(0, 0, 0, 0.4);
	--shadow-lg: 0 12px 24px -4px rgba(0, 0, 0, 0.5);
	--glow: rgba(34, 211, 238, 0.15);
}

* { box-sizing: border-box; }
body {
	margin: 0;
	background: var(--bg);
	color: var(--ink);
	font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
	font-size: 14px;
	line-height: 1.6;
	-webkit-font-smoothing: antialiased;
	transition: background-color 0.2s ease, color 0.2s ease;
}

.wrap {
	max-width: 1240px;
	margin: 0 auto;
	padding: 2rem 1.5rem 4rem;
}

/* Header & Top Bar */
.top-bar {
	display: flex;
	align-items: center;
	justify-content: space-between;
	margin-bottom: 1.5rem;
	gap: 1rem;
	flex-wrap: wrap;
}

.report-nav {
	display: flex;
	align-items: center;
	gap: 0.5rem;
	padding: 0.35rem 0.5rem;
	background: var(--card);
	border: 1px solid var(--line);
	border-radius: 999px;
	box-shadow: var(--shadow-sm);
}
.report-nav a {
	color: var(--muted);
	text-decoration: none;
	font-size: 0.78rem;
	font-weight: 600;
	text-transform: uppercase;
	letter-spacing: 0.06em;
	padding: 0.4rem 0.85rem;
	border-radius: 999px;
	transition: all 0.15s ease;
}
.report-nav a:hover {
	color: var(--ink);
	background: var(--panel-soft);
}

.top-actions {
	display: flex;
	align-items: center;
	gap: 0.6rem;
}

.btn-action {
	display: inline-flex;
	align-items: center;
	gap: 0.45rem;
	background: var(--card);
	border: 1px solid var(--line);
	color: var(--ink);
	font-family: inherit;
	font-size: 0.82rem;
	font-weight: 600;
	padding: 0.45rem 0.9rem;
	border-radius: 999px;
	cursor: pointer;
	box-shadow: var(--shadow-sm);
	transition: all 0.15s ease;
}
.btn-action:hover {
	background: var(--bg-subtle);
	border-color: var(--accent);
	color: var(--accent);
}

/* Hero Section */
.report-hero {
	padding: 2.2rem 2.5rem;
	background: var(--card);
	border: 1px solid var(--line);
	border-radius: var(--radius-lg);
	margin-bottom: 1.5rem;
	box-shadow: var(--shadow-md);
	position: relative;
	overflow: hidden;
}
.report-hero::before {
	content: '';
	position: absolute;
	top: 0;
	left: 0;
	right: 0;
	height: 4px;
	background: linear-gradient(90deg, #0284c7, #22d3ee, #6366f1);
}
.hero-flex {
	display: flex;
	align-items: center;
	justify-content: space-between;
	gap: 2rem;
	flex-wrap: wrap;
}
.hero-main { max-width: 800px; }
.hero-kicker {
	color: var(--accent);
	font-size: 0.75rem;
	font-weight: 800;
	text-transform: uppercase;
	letter-spacing: 0.1em;
	margin-bottom: 0.4rem;
	display: inline-block;
}
.report-hero h1 {
	margin: 0 0 0.5rem;
	font-size: 2.1rem;
	font-weight: 800;
	letter-spacing: -0.03em;
	color: var(--ink-heading);
	line-height: 1.2;
}
.report-hero p.sub {
	margin: 0;
	color: var(--muted);
	font-size: 0.95rem;
	line-height: 1.5;
}
.hero-total {
	min-width: 170px;
	padding: 1.2rem 1.4rem;
	border: 1px solid var(--line);
	border-radius: var(--radius);
	background: var(--bg-subtle);
	text-align: right;
}
.hero-total strong {
	display: block;
	font-size: 2.4rem;
	font-weight: 800;
	line-height: 1;
	color: var(--ink-heading);
}
.hero-total span {
	color: var(--muted);
	font-size: 0.72rem;
	text-transform: uppercase;
	letter-spacing: 0.08em;
	font-weight: 700;
}

/* Vulnerabilities At a Glance */
.vulnerability-overview { margin: 2rem 0; }
.section-heading {
	display: flex;
	align-items: flex-end;
	justify-content: space-between;
	gap: 1.5rem;
	margin-bottom: 1.1rem;
}
.section-heading h2 {
	margin: 0.2rem 0 0.15rem;
	font-size: 1.5rem;
	font-weight: 800;
	letter-spacing: -0.02em;
	color: var(--ink-heading);
}
.section-heading p { margin: 0; color: var(--muted); font-size: 0.88rem; }
.eyebrow {
	color: var(--accent);
	font-size: 0.72rem;
	font-weight: 800;
	text-transform: uppercase;
	letter-spacing: 0.12em;
}
.text-action {
	color: var(--accent);
	background: transparent;
	border: 0;
	padding: 0.5rem;
	font: inherit;
	font-size: 0.84rem;
	font-weight: 700;
	cursor: pointer;
	white-space: nowrap;
}
.text-action:hover { text-decoration: underline; }

.vulnerability-grid {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
	gap: 0.85rem;
}
.vulnerability-tile {
	position: relative;
	display: grid;
	grid-template-columns: auto 1fr auto;
	align-items: center;
	gap: 0.85rem;
	min-width: 0;
	padding: 1rem 1.15rem;
	color: var(--ink);
	text-align: left;
	background: var(--card);
	border: 1px solid var(--line);
	border-radius: var(--radius);
	cursor: pointer;
	box-shadow: var(--shadow-sm);
	transition: transform 0.15s ease, border-color 0.15s ease, box-shadow 0.15s ease;
}
.vulnerability-tile:hover {
	transform: translateY(-2px);
	border-color: var(--accent);
	box-shadow: var(--shadow-md);
}
.tile-rank {
	color: var(--muted);
	font-family: 'JetBrains Mono', Consolas, monospace;
	font-size: 0.72rem;
	font-weight: 600;
}
.tile-copy { min-width: 0; }
.tile-copy strong {
	display: block;
	color: var(--ink-heading);
	font-size: 0.9rem;
	font-weight: 700;
	line-height: 1.3;
}
.tile-copy small {
	display: block;
	margin-top: 0.15rem;
	color: var(--muted);
	font-family: 'JetBrains Mono', Consolas, monospace;
	font-size: 0.68rem;
	text-transform: uppercase;
}
.tile-count {
	display: grid;
	place-items: center;
	min-width: 2.3rem;
	height: 2.3rem;
	padding: 0 0.5rem;
	border-radius: 10px;
	color: var(--accent);
	background: var(--accent-soft);
	border: 1px solid rgba(2, 132, 199, 0.15);
	font-size: 1.15rem;
	font-weight: 800;
}

.empty-state {
	display: flex;
	flex-direction: column;
	gap: 0.25rem;
	padding: 1.75rem;
	border: 1px dashed var(--line);
	border-radius: var(--radius);
	background: var(--card);
	text-align: center;
}
.empty-state strong { color: var(--ink-heading); font-size: 0.95rem; }
.empty-state span { color: var(--muted); font-size: 0.85rem; }

/* Grid for Metadata, Risk, and Breakdown */
.report-grid {
	display: grid;
	grid-template-columns: 1.3fr 1fr 1.7fr;
	gap: 1.25rem;
	margin-bottom: 2rem;
}
@media (max-width: 1024px) {
	.report-grid { grid-template-columns: 1fr; }
}

.card {
	background: var(--card);
	border: 1px solid var(--line);
	border-radius: var(--radius);
	padding: 1.5rem;
	margin-bottom: 1.25rem;
	box-shadow: var(--shadow-sm);
}

.meta-card, .risk-card, .breakdown-card {
	display: flex;
	flex-direction: column;
	justify-content: space-between;
}
.meta-card h3, .risk-card h3, .breakdown-card h3 {
	margin: 0 0 1rem;
	font-size: 0.85rem;
	font-weight: 700;
	color: var(--muted);
	text-transform: uppercase;
	letter-spacing: 0.06em;
}

.meta-table {
	width: 100%%;
	border-collapse: collapse;
	font-size: 0.86rem;
}
.meta-table td {
	padding: 0.4rem 0;
	color: var(--ink);
	border-bottom: 1px solid var(--line-subtle);
}
.meta-table tr:last-child td { border-bottom: none; }
.meta-table td:first-child {
	color: var(--muted);
	width: 40%%;
	font-weight: 500;
}
.meta-table code {
	background: var(--code-bg);
	color: var(--code-ink);
	padding: 0.15rem 0.45rem;
	border-radius: 6px;
	font-family: 'JetBrains Mono', Consolas, monospace;
	font-size: 0.76rem;
}

.risk-card {
	text-align: center;
	align-items: center;
}
.risk-gauge {
	font-size: 1.3rem;
	font-weight: 800;
	padding: 0.65rem 1.6rem;
	border-radius: 999px;
	text-transform: uppercase;
	letter-spacing: 0.05em;
	display: inline-block;
	margin: 0.5rem 0;
}
.risk-desc {
	margin: 0.5rem 0 0;
	font-size: 0.76rem;
	color: var(--muted);
	line-height: 1.4;
}

.risk-card.risk-critical .risk-gauge { background: var(--crit-bg); color: var(--crit-ink); border: 1.5px solid var(--crit-border); }
.risk-card.risk-high .risk-gauge { background: var(--high-bg); color: var(--high-ink); border: 1.5px solid var(--high-border); }
.risk-card.risk-medium .risk-gauge { background: var(--med-bg); color: var(--med-ink); border: 1.5px solid var(--med-border); }
.risk-card.risk-low .risk-gauge { background: var(--low-bg); color: var(--low-ink); border: 1.5px solid var(--low-border); }
.risk-card.risk-info .risk-gauge { background: var(--info-bg); color: var(--info-ink); border: 1.5px solid var(--info-border); }

.breakdown-grid {
	display: grid;
	grid-template-columns: repeat(5, 1fr);
	gap: 0.6rem;
	width: 100%%;
}
.b-box {
	display: flex;
	flex-direction: column;
	align-items: center;
	justify-content: center;
	padding: 0.85rem 0.4rem;
	border-radius: var(--radius);
	border: 1px solid var(--line);
	background: var(--bg-subtle);
	transition: all 0.15s ease;
}
.b-box:hover { transform: translateY(-2px); }
.b-box .cnt {
	font-size: 1.6rem;
	font-weight: 800;
	line-height: 1.1;
}
.b-box .lbl {
	font-size: 0.68rem;
	color: var(--muted);
	font-weight: 700;
	text-transform: uppercase;
	letter-spacing: 0.05em;
	margin-top: 0.35rem;
}
.b-box.crit .cnt { color: var(--crit); }
.b-box.high .cnt { color: var(--high); }
.b-box.med .cnt { color: var(--med); }
.b-box.low .cnt { color: var(--low); }
.b-box.info .cnt { color: var(--info); }

/* Report Sections */
section.report-section {
	margin-bottom: 2.5rem;
}
section.report-section > h2 {
	font-size: 1.35rem;
	font-weight: 800;
	margin: 0 0 1rem;
	padding-bottom: 0.6rem;
	border-bottom: 1px solid var(--line);
	color: var(--ink-heading);
	letter-spacing: -0.02em;
}

/* Metrics Cards */
.metrics {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
	gap: 1rem;
}
.metric {
	background: var(--card);
	border: 1px solid var(--line);
	border-radius: var(--radius);
	padding: 1.25rem;
	text-align: center;
	box-shadow: var(--shadow-sm);
}
.metric .n {
	font-size: 2.2rem;
	font-weight: 800;
	color: var(--ink-heading);
	line-height: 1;
	margin-bottom: 0.4rem;
}
.metric .l {
	color: var(--muted);
	font-size: 0.74rem;
	text-transform: uppercase;
	letter-spacing: 0.08em;
	font-weight: 700;
}

/* Filter Controls */
.filter-controls {
	display: flex;
	align-items: center;
	justify-content: space-between;
	gap: 1rem;
	margin-bottom: 1.25rem;
	flex-wrap: wrap;
	background: var(--card);
	border: 1px solid var(--line);
	padding: 0.85rem 1.1rem;
	border-radius: var(--radius);
	box-shadow: var(--shadow-sm);
}
.filter-controls input[type="text"] {
	flex: 1;
	min-width: 240px;
	background: var(--bg-subtle);
	border: 1px solid var(--line);
	color: var(--ink);
	padding: 0.55rem 0.95rem;
	border-radius: 8px;
	font-family: inherit;
	font-size: 0.86rem;
	outline: none;
	transition: border-color 0.15s ease;
}
.filter-controls input[type="text"]:focus {
	border-color: var(--accent);
	background: var(--card);
}
.filter-status {
	font-size: 0.8rem;
	color: var(--muted);
	font-weight: 600;
}
.filter-buttons {
	display: flex;
	gap: 0.4rem;
	flex-wrap: wrap;
}
.filter-btn {
	background: var(--bg-subtle);
	border: 1px solid var(--line);
	color: var(--muted);
	padding: 0.4rem 0.75rem;
	border-radius: 6px;
	font-family: inherit;
	font-size: 0.76rem;
	font-weight: 700;
	cursor: pointer;
	text-transform: uppercase;
	letter-spacing: 0.04em;
	transition: all 0.15s ease;
}
.filter-btn:hover {
	color: var(--ink);
	border-color: var(--accent);
}
.filter-btn.active {
	background: var(--accent);
	color: #ffffff;
	border-color: var(--accent);
}

/* Finding Cards */
.findings-list {
	display: flex;
	flex-direction: column;
	gap: 1.25rem;
}
.finding {
	background: var(--card);
	border: 1px solid var(--line);
	border-radius: var(--radius);
	padding: 1.75rem;
	position: relative;
	box-shadow: var(--shadow-sm);
	transition: box-shadow 0.15s ease, border-color 0.15s ease;
	break-inside: avoid;
}
.finding:hover {
	box-shadow: var(--shadow-md);
	border-color: var(--accent);
}
.finding.sev-critical { border-left: 5px solid var(--crit); }
.finding.sev-high { border-left: 5px solid var(--high); }
.finding.sev-medium { border-left: 5px solid var(--med); }
.finding.sev-low { border-left: 5px solid var(--low); }
.finding.sev-info { border-left: 5px solid var(--info); }

.finding h3 {
	margin: 0 0 0.6rem;
	font-size: 1.25rem;
	font-weight: 800;
	color: var(--ink-heading);
	letter-spacing: -0.01em;
}
.finding h4 {
	margin: 1.4rem 0 0.5rem;
	font-size: 0.95rem;
	font-weight: 800;
	color: var(--ink-heading);
	letter-spacing: -0.01em;
}
.finding p, .finding ol, .finding ul {
	color: var(--ink);
	font-size: 0.9rem;
	margin: 0 0 0.85rem;
	line-height: 1.6;
}
.finding ol, .finding ul { padding-left: 1.35rem; }
.finding li { margin-bottom: 0.35rem; }

.badge {
	display: inline-block;
	padding: 0.25rem 0.65rem;
	border-radius: 6px;
	font-size: 0.72rem;
	font-weight: 800;
	text-transform: uppercase;
	letter-spacing: 0.05em;
	margin-right: 0.5rem;
}
.badge-critical { background: var(--crit-bg); color: var(--crit-ink); border: 1px solid var(--crit-border); }
.badge-high { background: var(--high-bg); color: var(--high-ink); border: 1px solid var(--high-border); }
.badge-medium { background: var(--med-bg); color: var(--med-ink); border: 1px solid var(--med-border); }
.badge-low { background: var(--low-bg); color: var(--low-ink); border: 1px solid var(--low-border); }
.badge-info { background: var(--info-bg); color: var(--info-ink); border: 1px solid var(--info-border); }

.meta-line {
	font-size: 0.82rem;
	color: var(--muted);
	margin-bottom: 1.1rem;
	display: flex;
	align-items: center;
	flex-wrap: wrap;
	gap: 0.5rem;
}
.meta-line code {
	background: var(--code-bg);
	color: var(--code-ink);
	padding: 0.15rem 0.45rem;
	border-radius: 5px;
	font-family: 'JetBrains Mono', Consolas, monospace;
	font-size: 0.78rem;
}

dl.kv {
	display: grid;
	grid-template-columns: max-content 1fr;
	gap: 0.45rem 1.25rem;
	background: var(--bg-subtle);
	padding: 1.1rem 1.25rem;
	border-radius: var(--radius);
	border: 1px solid var(--line);
	font-size: 0.86rem;
	margin: 1.1rem 0;
}
dl.kv dt {
	color: var(--muted);
	font-weight: 700;
}
dl.kv dd {
	margin: 0;
	color: var(--ink);
	word-break: break-all;
}
dl.kv dd code {
	background: transparent;
	padding: 0;
	color: var(--accent);
	font-family: 'JetBrains Mono', Consolas, monospace;
	font-weight: 600;
}

/* Payloads & Code Blocks */
.payload-box {
	background: var(--code-bg);
	color: var(--code-ink);
	border: 1px solid var(--line);
	border-radius: 8px;
	padding: 0.85rem 1rem;
	font-family: 'JetBrains Mono', Consolas, monospace;
	font-size: 0.84rem;
	word-break: break-all;
	margin: 0.6rem 0 1rem;
}

pre.http {
	background: var(--http-bg);
	color: var(--http-ink);
	padding: 1.1rem;
	border-radius: 8px;
	border: 1px solid var(--http-border);
	font-family: 'JetBrains Mono', Consolas, monospace;
	font-size: 0.8rem;
	line-height: 1.5;
	overflow-x: auto;
	white-space: pre-wrap;
	word-break: break-all;
	margin: 0.5rem 0 1rem;
}

details {
	margin: 0.6rem 0;
}
details summary {
	cursor: pointer;
	font-weight: 700;
	color: var(--accent);
	font-size: 0.85rem;
	user-select: none;
	padding: 0.35rem 0;
}
details summary:hover {
	text-decoration: underline;
}

.vuln-hit {
	background: #fef08a;
	color: #854d0e;
	font-weight: 700;
	padding: 0.1rem 0.3rem;
	border-radius: 4px;
	box-shadow: 0 0 0 1px rgba(133, 77, 14, 0.2);
}
html[data-theme="dark"] .vuln-hit {
	background: #ca8a04;
	color: #fef08a;
}

/* Tables */
table.data {
	width: 100%%;
	border-collapse: collapse;
	margin: 0.5rem 0;
	font-size: 0.86rem;
}
table.data th {
	background: var(--bg-subtle);
	color: var(--muted);
	text-transform: uppercase;
	font-size: 0.72rem;
	font-weight: 700;
	letter-spacing: 0.06em;
	text-align: left;
	padding: 0.75rem 1rem;
	border-bottom: 1px solid var(--line);
}
table.data td {
	padding: 0.75rem 1rem;
	border-bottom: 1px solid var(--line);
	color: var(--ink);
}
table.data tr:hover td {
	background: var(--bg-subtle);
}

ul.scope {
	padding-left: 1.25rem;
	margin: 0.5rem 0 1rem;
}
ul.scope li {
	margin-bottom: 0.35rem;
	font-family: 'JetBrains Mono', Consolas, monospace;
	font-size: 0.86rem;
}

/* Copy Buttons & Code Headers */
.code-header {
	display: flex;
	align-items: center;
	justify-content: space-between;
	margin-bottom: 0.4rem;
}
.copy-btn {
	background: var(--bg-subtle);
	border: 1px solid var(--line);
	color: var(--ink);
	font-size: 0.72rem;
	font-weight: 700;
	padding: 0.25rem 0.55rem;
	border-radius: 5px;
	cursor: pointer;
	transition: all 0.15s ease;
	display: inline-flex;
	align-items: center;
	gap: 0.3rem;
}
.copy-btn:hover {
	border-color: var(--accent);
	background: var(--card);
}
.copy-btn.copied {
	background: #10b981 !important;
	color: #ffffff !important;
	border-color: #10b981 !important;
}

/* Toast notification */
#akca-toast {
	position: fixed;
	bottom: 1.5rem;
	right: 1.5rem;
	background: #1e293b;
	color: #ffffff;
	padding: 0.7rem 1.2rem;
	border-radius: 8px;
	box-shadow: var(--shadow-md);
	font-size: 0.85rem;
	font-weight: 600;
	opacity: 0;
	pointer-events: none;
	transition: opacity 0.2s ease, transform 0.2s ease;
	transform: translateY(10px);
	z-index: 9999;
}
#akca-toast.show {
	opacity: 1;
	transform: translateY(0);
}

/* Print Friendly Styles */
@media print {
	body {
		background: #ffffff !important;
		color: #000000 !important;
		font-size: 12px !important;
	}
	.wrap { max-width: 100%% !important; padding: 0 !important; }
	.top-bar, .filter-controls, .text-action, .report-nav, .top-actions { display: none !important; }
	.card, .finding {
		box-shadow: none !important;
		border: 1px solid #cbd5e1 !important;
		background: #ffffff !important;
		break-inside: avoid !important;
		page-break-inside: avoid !important;
	}
	.report-hero {
		background: #f8fafc !important;
		border: 1px solid #cbd5e1 !important;
	}
	details { display: block !important; }
	details[open] summary, details summary { display: none !important; }
	pre.http {
		background: #f8fafc !important;
		color: #000000 !important;
		border: 1px solid #cbd5e1 !important;
	}
	.vuln-hit { background: #fef08a !important; color: #000000 !important; }
}
</style></head><body><div class="wrap">
<div class="top-bar">
  <nav class="report-nav" aria-label="Report sections">
    <a href="#overview">Overview</a><a href="#findings">Findings</a><a href="#metrics">Metrics</a><a href="#scope">Scope</a><a href="#traffic">Evidence</a>
  </nav>
  <div class="top-actions">
    <button type="button" class="btn-action" id="themeToggleBtn" onclick="toggleReportTheme()">
      <span id="themeIcon">🌙</span> <span id="themeLabel">Dark Mode</span>
    </button>
    <button type="button" class="btn-action" onclick="window.print()">
      <span>🖨️</span> <span>Print / PDF</span>
    </button>
  </div>
</div>
<header class="report-hero">
  <div class="hero-flex">
    <div class="hero-main">
      <span class="hero-kicker">%s</span>
      <h1>%s</h1>
      <p class="sub">%s</p>
    </div>
    <div class="hero-total"><strong>%d</strong><span>Reportable findings</span></div>
  </div>
</header>
%s
<div class="report-grid">
  <div class="card meta-card">
    <h3>Scan Information</h3>
    <table class="meta-table">
      <tr><td>Target:</td><td><strong>%s</strong></td></tr>
      <tr><td>Scan ID:</td><td><code>%s</code></td></tr>
      <tr><td>Started:</td><td>%s</td></tr>
      <tr><td>Finished:</td><td>%s</td></tr>
      <tr><td>Duration:</td><td><strong>%s</strong></td></tr>
      <tr><td>Requests / Probes:</td><td><strong>%d sent</strong></td></tr>
      <tr><td>Report Generated:</td><td>%s</td></tr>
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
		template.HTMLEscapeString(ProductName),
		template.HTMLEscapeString(meta.Title),
		template.HTMLEscapeString(meta.Summary),
		meta.Metrics.TotalFindings,
		vulnerabilityOverviewHTML(meta.Metrics),
		template.HTMLEscapeString(targetsStr),
		template.HTMLEscapeString(meta.Scope.ScanID),
		template.HTMLEscapeString(startedStr),
		template.HTMLEscapeString(finishedStr),
		template.HTMLEscapeString(durationStr),
		totalReqs,
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
// Theme Management
function initTheme() {
    const saved = localStorage.getItem('akca_report_theme');
    if (saved === 'dark' || (!saved && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
        setTheme('dark');
    } else {
        setTheme('light');
    }
}

function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('akca_report_theme', theme);
    const icon = document.getElementById('themeIcon');
    const label = document.getElementById('themeLabel');
    if (theme === 'dark') {
        if (icon) icon.textContent = '☀️';
        if (label) label.textContent = 'Light Mode';
    } else {
        if (icon) icon.textContent = '🌙';
        if (label) label.textContent = 'Dark Mode';
    }
}

function toggleReportTheme() {
    const current = document.documentElement.getAttribute('data-theme') || 'light';
    setTheme(current === 'light' ? 'dark' : 'light');
}

// Findings Filtering & Search
let activeSeverity = 'all';
let activeClass = 'all';

function setSeverityFilter(sev, btn) {
    activeSeverity = (sev || 'all').toLowerCase();
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');
    applyFilters();
}

function setClassFilter(vulnClass) {
    activeClass = (vulnClass || 'all').toLowerCase();
    applyFilters();
    const findingsEl = document.getElementById('findings') || document.querySelector('.findings-list');
    if (findingsEl) findingsEl.scrollIntoView({behavior: 'smooth', block: 'start'});
}

function applyFilters() {
    const searchInput = document.getElementById('vulnSearch');
    const q = searchInput ? searchInput.value.toLowerCase().trim() : '';
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
    if (!text && btn) {
        const target = btn.getAttribute('data-copy') || (btn.nextElementSibling ? btn.nextElementSibling.textContent : '');
        text = target;
    }
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
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
initTheme();
</script>
<div id="akca-toast">✓ Copied to clipboard!</div>
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
	b.WriteString(`Confidence: <strong>` + template.HTMLEscapeString(f.Confidence) +
		`</strong> · Class: <code>` + template.HTMLEscapeString(f.VulnClass) + `</code></p>`)
	if len(f.CWE) > 0 || len(f.OWASPTop102025) > 0 {
		b.WriteString(`<p class="meta-line">`)
		if len(f.CWE) > 0 {
			b.WriteString(`CWE: <code>` + template.HTMLEscapeString(strings.Join(f.CWE, ", ")) + `</code>`)
		}
		if len(f.CWE) > 0 && len(f.OWASPTop102025) > 0 {
			b.WriteString(` · `)
		}
		if len(f.OWASPTop102025) > 0 {
			b.WriteString(`OWASP: <code>` + template.HTMLEscapeString(strings.Join(f.OWASPTop102025, ", ")) + `</code>`)
		}
		b.WriteString(`</p>`)
	}

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
		b.WriteString(`<details><summary>▼ Show Raw HTTP Request</summary><div class="code-header"><span>HTTP Request</span><button type="button" class="copy-btn" onclick="copyToClipboard(this)">📋 Copy Request</button></div><pre class="http">` +
			highlightEvidence(template.HTMLEscapeString(ev.RawRequest), []string{ev.Payload}) + `</pre></details>`)
	}
	if ev.RawResponse != "" {
		b.WriteString(`<details><summary>▼ Show Raw HTTP Response (proof highlighted)</summary><div class="code-header"><span>HTTP Response</span><button type="button" class="copy-btn" onclick="copyToClipboard(this)">📋 Copy Response</button></div><pre class="http">` +
			highlightEvidence(template.HTMLEscapeString(ev.RawResponse), markers) + `</pre></details>`)
	}
	if ev.CurlCommand != "" {
		b.WriteString(`<details><summary>▼ Show cURL Command (Reproduce)</summary><div class="code-header"><span>cURL Reproduction Command</span><button type="button" class="copy-btn" onclick="copyToClipboard(this)">📋 Copy cURL</button></div><pre class="http">` + template.HTMLEscapeString(ev.CurlCommand) + `</pre></details>`)
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
