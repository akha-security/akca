package modules

import (
	"context"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

func (r *Runner) runOpenRedirect(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("open_redirect", target); !ok {
		r.emitSkip("open_redirect", target, reason)
		return nil
	}
	var out []ModuleFinding
	baseline, err := r.probe(ctx, target, "/")
	if err != nil {
		return nil
	}
	probes := []struct{ value, signal string }{
		{"https://evil.example/akca", "parameter_redirect"},
		{"//evil.example/akca", "protocol_relative"},
		{"/\\evil.example", "path_confusion"},
		{"javascript:alert(1)", "javascript_uri"},
	}
	for _, pr := range probes {
		rr, err := r.probe(ctx, target, pr.value)
		if err != nil {
			continue
		}
		if !openRedirectSignal(rr, pr.value) {
			continue
		}
		p := defaultPayload("open_redirect", pr.signal, pr.value, pr.signal)
		f := r.verifyAndBuild(ctx, "open_redirect", target, p, baseline, rr, pr.signal, false, false, "", "")
		r.recordFinding(&out, f, "open_redirect", pr.signal)
	}
	return out
}

func openRedirectSignal(rr httpclient.RequestResponse, value string) bool {
	status := rr.Response.StatusCode
	if status < 300 || status > 308 {
		return false
	}
	loc := ""
	for k, v := range rr.Response.Headers {
		if strings.EqualFold(k, "Location") {
			loc = strings.TrimSpace(v)
			break
		}
	}
	if loc == "" {
		return false
	}
	low := strings.ToLower(loc)
	// Redirect target points at our injected external host.
	if strings.Contains(low, "evil.example") {
		return true
	}
	// javascript: scheme reflected into the Location header. Without this branch
	// the javascript_uri probe could never produce a signal (dead code).
	if strings.HasPrefix(low, "javascript:") && strings.Contains(strings.ToLower(value), "javascript:") {
		return true
	}
	return false
}

func (r *Runner) runHostHeader(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("host_header", target); !ok {
		r.emitSkip("host_header", target, reason)
		return nil
	}
	var out []ModuleFinding
	baseline, _ := r.cachedEmptyHeaderProbe(ctx, target)
	headers := map[string]string{"Host": "evil.akca.local", "X-Forwarded-Host": "evil.akca.local"}
	rr, err := r.probeWithHeaders(ctx, target, "", headers)
	if err != nil {
		return nil
	}
	if hostHeaderSignal(rr.Response.Body, baseline.Response.Body) {
		p := defaultPayload("host_header", "password_reset_poison", "evil.akca.local", "host_reflection")
		f := r.verifyAndBuild(ctx, "host_header", target, p, baseline, rr, "host_injection", false, false, "", "")
		r.recordFinding(&out, f, "host_header", "host_injection")
	}
	return out
}

func hostHeaderSignal(body, baseline string) bool {
	return strings.Contains(strings.ToLower(body), "evil.akca.local") && body != baseline
}
