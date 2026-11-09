package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"net/url"
	"strings"
)

//go:embed professional.css
var professionalReportCSS string

func professionalDocStart(meta Document) string {
	esc := template.HTMLEscapeString
	target := "Assessment scope"
	if len(meta.Scope.Targets) > 0 {
		target = meta.Scope.Targets[0]
		if u, err := url.Parse(target); err == nil && u.Host != "" {
			target = u.Host
		}
		if len(meta.Scope.Targets) > 1 {
			target += fmt.Sprintf(" + %d other targets", len(meta.Scope.Targets)-1)
		}
	}
	status := "Completed"
	if meta.Partial {
		status = "Partial scan"
	}
	highest, riskClass := "None identified", "info"
	for _, severity := range []string{"critical", "high", "medium", "low", "info"} {
		if meta.Metrics.BySeverity[severity] > 0 {
			highest = map[string]string{"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Informational"}[severity]
			riskClass = severity
			break
		}
	}
	if meta.Partial && meta.Metrics.TotalFindings == 0 {
		highest = "Inconclusive"
	}
	title := meta.Title
	if title == "" || title == ProductName {
		title = "Application security assessment"
	}
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html lang="en" data-theme="light"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="application-name" content="` + esc(ProductName) + `"><title>` + esc(title) + `</title><style>` + professionalReportCSS + `</style></head><body><div class="wrap">`)
	b.WriteString(`<div class="report-toolbar"><span class="toolbar-label"><strong>AKCA</strong><span>SECURITY REPORT</span></span><button type="button" class="btn-action" onclick="window.print()">Print / PDF</button></div>`)
	b.WriteString(`<header class="report-header"><img class="report-logo" src="` + reportLogoURL + `" alt="AKCA logo" width="148" height="148"><p class="report-brand-name">AKCA Advanced Web Security Scanner</p><div class="report-cover-rule"></div><p class="eyebrow">SECURITY ASSESSMENT REPORT</p><h1>` + esc(title) + `</h1><div class="report-cover-meta"><div><span>TARGET</span><strong class="report-target">` + esc(target) + `</strong></div><div class="report-date"><span>REPORT GENERATED</span><strong>` + esc(meta.GeneratedAt.Format("02 Jan 2006")) + `</strong></div></div></header>`)
	if meta.Summary != "" {
		b.WriteString(`<p class="report-intro">` + esc(meta.Summary) + `</p>`)
	}
	b.WriteString(`<nav class="report-nav" aria-label="Report sections"><a href="#overview">Overview</a><a href="#findings">Findings</a><a href="#scope">Scope</a>`)
	if len(meta.ManualLeads) > 0 && meta.Template != TemplateExecutive {
		b.WriteString(`<a href="#manual-leads">Review leads</a>`)
	}
	if len(meta.Coverage) > 0 && meta.Template != TemplateExecutive {
		b.WriteString(`<a href="#coverage">Coverage</a>`)
	}
	if len(meta.TrafficEvidence) > 0 && meta.Template != TemplateExecutive {
		b.WriteString(`<a href="#traffic">HTTP evidence</a>`)
	}
	b.WriteString(`</nav>`)
	if meta.Partial {
		b.WriteString(`<div class="coverage-warning"><strong>Partial scan</strong><span>Some checks could not complete. Review coverage limitations before interpreting the results.</span></div>`)
	}
	b.WriteString(`<section id="overview" class="overview-section"><div class="section-heading"><h2>Assessment overview</h2><span class="scan-status`)
	if meta.Partial {
		b.WriteString(` partial`)
	}
	b.WriteString(`">` + esc(status) + `</span></div><div class="summary-grid">`)
	b.WriteString(fmt.Sprintf(`<div class="summary-stat"><span>Reportable findings</span><strong>%d</strong></div><div class="summary-stat"><span>Highest severity</span><strong class="severity-text severity-%s">%s</strong></div><div class="summary-stat"><span>Requests sent</span><strong>%d</strong></div><div class="summary-stat"><span>Discovered endpoints</span><strong>%d</strong></div>`, meta.Metrics.TotalFindings, esc(riskClass), esc(highest), meta.Metrics.TotalRequests, meta.Metrics.EndpointCount))
	b.WriteString(`</div><div class="severity-summary" aria-label="Findings by severity">`)
	for _, severity := range []string{"critical", "high", "medium", "low", "info"} {
		label := map[string]string{"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}[severity]
		b.WriteString(fmt.Sprintf(`<span><i class="severity-dot severity-%s"></i>%s <strong>%d</strong></span>`, severity, label, meta.Metrics.BySeverity[severity]))
	}
	b.WriteString(`</div></section>`)
	b.WriteString(`<details class="assessment-details"><summary>Assessment details</summary><dl class="kv"><dt>Scan ID</dt><dd><code>` + esc(meta.Scope.ScanID) + `</code></dd><dt>Report type</dt><dd>` + esc(string(meta.Template)) + `</dd>`)
	for _, detail := range []struct{ label, value string }{{"Started", meta.Metrics.StartedAt}, {"Finished", meta.Metrics.FinishedAt}, {"Duration", meta.Metrics.Duration}, {"Scanner version", meta.EngineVersion}} {
		if detail.value != "" && detail.value != "unknown" {
			b.WriteString(`<dt>` + detail.label + `</dt><dd>` + esc(detail.value) + `</dd>`)
		}
	}
	b.WriteString(`</dl></details>`)
	if meta.Template != TemplateExecutive {
		b.WriteString(vulnerabilityOverviewHTML(meta.Metrics))
	}
	return b.String()
}

func endpointPresentation(raw string) (string, bool) {
	if len(raw) <= 160 {
		return raw, false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw, true
	}
	u.RawQuery, u.Fragment = "", ""
	return u.String(), true
}
