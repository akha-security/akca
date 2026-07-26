package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/storage"
)

type Exporter struct {
	builder  *Builder
	progress ProgressFunc
}

func NewExporter(builder *Builder, progress ProgressFunc) *Exporter {
	if progress == nil {
		progress = func(Progress) {}
	}
	return &Exporter{builder: builder, progress: progress}
}

func (e *Exporter) Export(w io.Writer, opts Options) error {
	switch opts.Format {
	case FormatHTML:
		return e.ExportHTML(w, opts)
	case FormatJSON:
		return e.ExportJSON(w, opts)
	case FormatCSV:
		return e.ExportCSV(w, opts)
	case FormatMarkdown:
		return e.ExportMarkdown(w, opts)
	case FormatSARIF:
		return e.ExportSARIF(w, opts)
	default:
		return fmt.Errorf("unsupported format: %s", opts.Format)
	}
}

func (e *Exporter) ExportSARIF(w io.Writer, opts Options) error {
	type sarifMessage struct {
		Text string `json:"text"`
	}
	type sarifArtifact struct {
		URI string `json:"uri"`
	}
	type sarifLocation struct {
		PhysicalLocation struct {
			ArtifactLocation sarifArtifact `json:"artifactLocation"`
		} `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID     string                 `json:"ruleId"`
		Level      string                 `json:"level"`
		Message    sarifMessage           `json:"message"`
		Locations  []sarifLocation        `json:"locations,omitempty"`
		Properties map[string]interface{} `json:"properties,omitempty"`
	}
	type sarifRule struct {
		ID               string       `json:"id"`
		Name             string       `json:"name"`
		ShortDescription sarifMessage `json:"shortDescription"`
	}
	type sarifDriver struct {
		Name           string      `json:"name"`
		InformationURI string      `json:"informationUri"`
		Rules          []sarifRule `json:"rules"`
	}
	type sarifRun struct {
		Tool struct {
			Driver sarifDriver `json:"driver"`
		} `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	document := struct {
		Version string     `json:"version"`
		Schema  string     `json:"$schema"`
		Runs    []sarifRun `json:"runs"`
	}{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs:    []sarifRun{{}},
	}
	run := &document.Runs[0]
	run.Tool.Driver = sarifDriver{Name: "Akca", InformationURI: "https://github.com/"}
	ruleSeen := map[string]struct{}{}
	filter := e.builder.Filter(opts)
	err := e.builder.db.IterateFindingsFiltered(filter, func(rec storage.FindingRecord) error {
		entry, ok := e.builder.ReportFinding(rec, opts)
		if !ok {
			return nil
		}
		if _, exists := ruleSeen[entry.VulnClass]; !exists {
			ruleSeen[entry.VulnClass] = struct{}{}
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
				ID: entry.VulnClass, Name: entry.Title,
				ShortDescription: sarifMessage{Text: entry.Summary},
			})
		}
		result := sarifResult{
			RuleID: entry.VulnClass, Level: sarifLevel(entry.Severity),
			Message: sarifMessage{Text: entry.Description},
			Properties: map[string]interface{}{
				"confidence": entry.Confidence, "confidenceScore": entry.ConfidenceScore,
				"proofType": entry.HTTPEvidence.ProofType, "proofPolicy": entry.HTTPEvidence.ProofPolicy,
				"replayCommand": entry.ReplayCommand,
			},
		}
		if entry.EndpointURL != "" {
			location := sarifLocation{}
			location.PhysicalLocation.ArtifactLocation.URI = entry.EndpointURL
			result.Locations = []sarifLocation{location}
		}
		run.Results = append(run.Results, result)
		return nil
	})
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(document)
}

func sarifLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func (e *Exporter) ExportHTML(w io.Writer, opts Options) error {
	start := time.Now()
	e.emit(opts, "header", 5, 0)

	meta, err := e.builder.BuildMeta(opts)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, htmlDocStart(meta)); err != nil {
		return err
	}
	e.emit(opts, "scope", 15, 0)

	if err := renderHTMLSection(w, "scope", "Scope", scopeHTML(meta.Scope)); err != nil {
		return err
	}
	if err := renderHTMLSection(w, "metrics", "Scan Metrics", metricsHTML(meta.Metrics)); err != nil {
		return err
	}
	if opts.Template != TemplateExecutive {
		e.emit(opts, "api_keys", 25, 0)
		if err := renderHTMLSection(w, "api_keys", "API Keys / Tokens", apiKeysHTML(meta.APIKeyValidations)); err != nil {
			return err
		}
	}
	if opts.Template == TemplateExecutive {
		e.emit(opts, "executive_findings", 40, 0)
		if err := e.streamExecutiveFindingsHTML(w, opts); err != nil {
			return err
		}
	} else {
		e.emit(opts, "findings", 35, 0)
		if err := e.streamFindingsHTML(w, opts, meta.Template); err != nil {
			return err
		}
	}
	if len(meta.RootCauseGroups) > 0 && opts.Template != TemplateExecutive {
		e.emit(opts, "root_cause", 85, 0)
		if err := renderHTMLSection(w, "root_cause", "Root Cause Grouping", rootCauseHTML(meta.RootCauseGroups)); err != nil {
			return err
		}
	}
	if len(meta.ManualLeads) > 0 && opts.Template != TemplateExecutive {
		if err := renderHTMLSection(w, "manual-leads", "Passive & Manual Findings", manualLeadsHTML(meta.ManualLeads, meta.Template)); err != nil {
			return err
		}
	}
	if len(meta.TrafficEvidence) > 0 && opts.Template != TemplateExecutive {
		if err := renderHTMLSection(w, "traffic", "Crawling HTTP Traffic", trafficHTML(meta.TrafficEvidence)); err != nil {
			return err
		}
	}
	if opts.Template == TemplateAppendix {
		e.emit(opts, "appendix", 90, 0)
		if _, err := io.WriteString(w, `<section class="report-section"><h2>Appendix</h2><div class="card"><p>`+template.HTMLEscapeString(meta.AppendixNotes)+`</p></div></section>`); err != nil {
			return err
		}
	}
	e.emit(opts, "footer", 100, 0)
	_, err = io.WriteString(w, htmlDocEnd()+"<!-- generated in "+time.Since(start).String()+" -->")
	return err
}

func (e *Exporter) streamFindingsHTML(w io.Writer, opts Options, kind TemplateKind) error {
	filter := e.builder.Filter(opts)
	total := e.builder.CountReportableFindings(opts)
	if total == 0 {
		_, err := io.WriteString(w, `<section class="report-section"><h2>Findings</h2><div class="card"><p class="meta-line">No findings matched the selected filters.</p></div></section>`)
		return err
	}
	filterControls := `<div class="filter-controls">
		<input type="text" id="vulnSearch" placeholder="Search findings by title or class..." oninput="applyFilters()">
		<div class="filter-buttons">
			<button class="filter-btn active" onclick="setSeverityFilter('all', this)">All</button>
			<button class="filter-btn" data-sev="critical" onclick="setSeverityFilter('critical', this)">Critical</button>
			<button class="filter-btn" data-sev="high" onclick="setSeverityFilter('high', this)">High</button>
			<button class="filter-btn" data-sev="medium" onclick="setSeverityFilter('medium', this)">Medium</button>
			<button class="filter-btn" data-sev="low" onclick="setSeverityFilter('low', this)">Low</button>
			<button class="filter-btn" data-sev="info" onclick="setSeverityFilter('info', this)">Info</button>
		</div>
	</div>`
	if _, err := io.WriteString(w, `<section class="report-section"><h2>Findings</h2>`+filterControls+`<div class="findings-list">`); err != nil {
		return err
	}
	written := 0
	err := e.builder.db.IterateFindingsFiltered(filter, func(rec storage.FindingRecord) error {
		entry, ok := e.builder.ReportFinding(rec, opts)
		if !ok {
			return nil
		}
		block := findingHTML(entry, kind)
		if _, err := io.WriteString(w, block); err != nil {
			return err
		}
		written++
		pct := 35 + (written*45)/max(total, 1)
		e.emit(opts, "findings", pct, written)
		return nil
	})
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, `</div></section>`)
	return err
}

func (e *Exporter) streamExecutiveFindingsHTML(w io.Writer, opts Options) error {
	filter := e.builder.Filter(opts)
	if _, err := io.WriteString(w, `<section class="report-section"><h2>Executive Findings Overview</h2><div class="card"><table class="data"><thead><tr><th>Severity</th><th>Title</th><th>Endpoint</th></tr></thead><tbody>`); err != nil {
		return err
	}
	err := e.builder.db.IterateFindingsFiltered(filter, func(rec storage.FindingRecord) error {
		entry, ok := e.builder.ReportFinding(rec, opts)
		if !ok {
			return nil
		}
		row := fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td></tr>",
			template.HTMLEscapeString(entry.Severity),
			template.HTMLEscapeString(entry.Title),
			template.HTMLEscapeString(entry.EndpointURL))
		_, err := io.WriteString(w, row)
		return err
	})
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, `</tbody></table></div></section>`)
	return err
}

func (e *Exporter) ExportJSON(w io.Writer, opts Options) error {
	meta, err := e.builder.BuildMeta(opts)
	if err != nil {
		return err
	}
	e.emit(opts, "header", 10, 0)

	type headerDoc struct {
		SchemaVersion     string            `json:"schema_version"`
		GeneratedAt       interface{}       `json:"generated_at"`
		Template          TemplateKind      `json:"template"`
		Format            Format            `json:"format"`
		Partial           bool              `json:"partial"`
		Title             string            `json:"title"`
		Summary           string            `json:"summary"`
		Scope             ScopeSection      `json:"scope"`
		Metrics           interface{}       `json:"metrics"`
		RootCauseGroups   interface{}       `json:"root_cause_groups,omitempty"`
		APIKeyValidations []APIKeySection   `json:"api_key_validations,omitempty"`
		TrafficEvidence   []TrafficEntry    `json:"traffic_evidence,omitempty"`
		ManualLeads       []ManualLeadEntry `json:"manual_leads,omitempty"`
		AppendixNotes     string            `json:"appendix_notes,omitempty"`
	}
	hdr := headerDoc{
		SchemaVersion: meta.SchemaVersion,
		GeneratedAt:   meta.GeneratedAt, Template: meta.Template, Format: meta.Format,
		Partial: meta.Partial, Title: meta.Title, Summary: meta.Summary, Scope: meta.Scope,
		Metrics: meta.Metrics, RootCauseGroups: meta.RootCauseGroups,
		APIKeyValidations: meta.APIKeyValidations, AppendixNotes: meta.AppendixNotes,
		TrafficEvidence: meta.TrafficEvidence,
		ManualLeads:     meta.ManualLeads,
	}
	hdrBytes, err := json.Marshal(hdr)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, string(hdrBytes[:len(hdrBytes)-1])+`, "findings": [`); err != nil {
		return err
	}

	filter := e.builder.Filter(opts)
	total, _ := e.builder.db.CountFindingsFiltered(filter)
	written := 0
	first := true
	err = e.builder.db.IterateFindingsFiltered(filter, func(rec storage.FindingRecord) error {
		entry, ok := e.builder.ReportFinding(rec, opts)
		if !ok {
			return nil
		}
		if !first {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		first = false
		line, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		if _, err := w.Write(line); err != nil {
			return err
		}
		written++
		pct := 10 + (written*85)/max(total, 1)
		e.emit(opts, "findings", pct, written)
		return nil
	})
	if err != nil {
		return err
	}
	e.emit(opts, "footer", 100, written)
	_, err = io.WriteString(w, "]}\n")
	return err
}

func (e *Exporter) ExportCSV(w io.Writer, opts Options) error {
	cols := opts.CSVColumns
	if len(cols) == 0 {
		cols = []string{"id", "title", "severity", "confidence", "vuln_class", "endpoint_url", "parameter", "description"}
	}
	cw := csv.NewWriter(w)
	if err := cw.Write(cols); err != nil {
		return err
	}
	e.emit(opts, "header", 5, 0)

	filter := e.builder.Filter(opts)
	total, _ := e.builder.db.CountFindingsFiltered(filter)
	written := 0
	err := e.builder.db.IterateFindingsFiltered(filter, func(rec storage.FindingRecord) error {
		entry, ok := e.builder.ReportFinding(rec, opts)
		if !ok {
			return nil
		}
		row := csvRow(entry, cols)
		if err := cw.Write(row); err != nil {
			return err
		}
		written++
		if written%100 == 0 {
			cw.Flush()
			pct := 5 + (written*90)/max(total, 1)
			e.emit(opts, "rows", pct, written)
		}
		return nil
	})
	cw.Flush()
	e.emit(opts, "footer", 100, written)
	return err
}

func (e *Exporter) ExportMarkdown(w io.Writer, opts Options) error {
	meta, err := e.builder.BuildMeta(opts)
	if err != nil {
		return err
	}
	e.emit(opts, "header", 10, 0)
	if _, err := fmt.Fprintf(w, "# %s\n\n%s\n\n", meta.Title, meta.Summary); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "## Scope\n\nScan ID: `%s`\n\n", meta.Scope.ScanID); err != nil {
		return err
	}
	for _, t := range meta.Scope.Targets {
		if _, err := fmt.Fprintf(w, "- %s\n", t); err != nil {
			return err
		}
	}
	if len(meta.APIKeyValidations) > 0 {
		e.emit(opts, "api_keys", 20, 0)
		if _, err := io.WriteString(w, "\n## API Key / Token Validation\n\n"); err != nil {
			return err
		}
		for _, k := range meta.APIKeyValidations {
			if _, err := fmt.Fprintf(w, "### %s (%s)\n- Risk: %s\n- Remediation: %s\n\n", k.Service, k.Status, k.Risk, k.Remediation); err != nil {
				return err
			}
		}
	}
	filter := e.builder.Filter(opts)
	total, _ := e.builder.db.CountFindingsFiltered(filter)
	written := 0
	if _, err := io.WriteString(w, "\n## Findings\n\n"); err != nil {
		return err
	}
	err = e.builder.db.IterateFindingsFiltered(filter, func(rec storage.FindingRecord) error {
		entry, ok := e.builder.ReportFinding(rec, opts)
		if !ok {
			return nil
		}
		if _, err := io.WriteString(w, findingMarkdown(entry)); err != nil {
			return err
		}
		written++
		pct := 25 + (written*70)/max(total, 1)
		e.emit(opts, "findings", pct, written)
		return nil
	})
	if err == nil && len(meta.ManualLeads) > 0 {
		if _, writeErr := io.WriteString(w, "\n## Manual Leads\n\n> These leads were not automatically proven and are not bug-bounty submission ready.\n\n"); writeErr != nil {
			return writeErr
		}
		for _, lead := range meta.ManualLeads {
			if _, writeErr := io.WriteString(w, findingMarkdown(lead.Finding)); writeErr != nil {
				return writeErr
			}
		}
	}
	e.emit(opts, "footer", 100, written)
	return err
}

func csvRow(entry FindingEntry, cols []string) []string {
	row := make([]string, len(cols))
	for i, c := range cols {
		switch c {
		case "id":
			row[i] = fmt.Sprintf("%d", entry.ID)
		case "title":
			row[i] = entry.Title
		case "severity":
			row[i] = entry.Severity
		case "confidence":
			row[i] = entry.Confidence
		case "vuln_class":
			row[i] = entry.VulnClass
		case "endpoint_url":
			row[i] = entry.EndpointURL
		case "parameter":
			row[i] = entry.Parameter
		case "description":
			row[i] = entry.Description
		case "impact":
			row[i] = entry.Impact
		case "remediation":
			row[i] = entry.Remediation
		default:
			row[i] = ""
		}
	}
	return row
}

func (e *Exporter) emit(opts Options, section string, pct, rows int) {
	eta := ""
	if pct > 0 && pct < 100 {
		eta = fmt.Sprintf("~%ds remaining", (100-pct)/5)
	}
	e.progress(Progress{
		Format:      opts.Format,
		Section:     section,
		Percent:     pct,
		ETA:         eta,
		RowsWritten: rows,
		Template:    opts.Template,
	})
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
