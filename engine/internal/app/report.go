package app

import (
	"bytes"
	"context"
	"io"

	"github.com/akha-security/akca/engine/internal/evidencestore"
	"github.com/akha-security/akca/engine/internal/report"
)

func (e *Engine) runReportPhase(ctx context.Context, scanID string, partial bool) error {
	e.session.SetPhase("report_generation")
	_ = e.Emit("phase_started", "report generation", map[string]interface{}{"phase": "report_generation", "partial": partial})

	opts := report.Options{
		ScanID:   scanID,
		Template: report.TemplateInternal,
		Format:   report.FormatJSON,
		Partial:  partial,
		Redact:   e.session.Config.RedactReports,
	}
	if err := e.generateReport(ctx, opts); err != nil {
		return err
	}

	_ = e.Emit("phase_finished", "report generation", map[string]interface{}{"phase": "report_generation"})
	return nil
}

func (e *Engine) GenerateReport(opts report.Options) ([]byte, error) {
	return e.GenerateReportWithContext(context.Background(), opts)
}

func (e *Engine) GenerateReportWithContext(ctx context.Context, opts report.Options) ([]byte, error) {
	var buf bytes.Buffer
	if err := e.generateReportToWriter(ctx, &buf, opts); err != nil {
		return nil, err
	}
	if opts.Format == report.FormatJSON {
		if err := report.ValidateJSONSchema(buf.Bytes()); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func (e *Engine) generateReport(ctx context.Context, opts report.Options) error {
	_, err := e.GenerateReportWithContext(ctx, opts)
	return err
}

func (e *Engine) generateReportToWriter(ctx context.Context, w io.Writer, opts report.Options) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store := evidencestore.New(e.db)
	builder := report.NewBuilder(store, e.db)
	exporter := report.NewExporter(builder, func(p report.Progress) {
		_ = e.Emit("report_generation_progress", "report progress", map[string]interface{}{
			"format":       string(p.Format),
			"section":      p.Section,
			"percent":      p.Percent,
			"eta":          p.ETA,
			"rows_written": p.RowsWritten,
			"template":     string(p.Template),
		})
	})
	if err := exporter.Export(w, opts); err != nil {
		return err
	}
	doc, _ := builder.BuildMeta(opts)
	return store.SaveReportRecord(opts.ScanID, string(opts.Template), string(opts.Format), "", doc)
}
