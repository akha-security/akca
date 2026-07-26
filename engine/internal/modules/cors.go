package modules

import (
	"context"
	"net/url"
	"strings"
)

func (r *Runner) runCORS(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("cors", target); !ok {
		r.emitSkip("cors", target, reason)
		return nil
	}
	var out []ModuleFinding
	baseline, err := r.probeWithHeaders(ctx, target, "", map[string]string{"Origin": "https://benign.example"})
	if err != nil {
		return nil
	}
	targetHost := "example.com"
	if u, err := url.Parse(target.EndpointURL); err == nil && u.Hostname() != "" {
		targetHost = u.Hostname()
	}

	probes := []struct {
		origin, signal string
	}{
		{"null", "null_origin"},
		{"https://evil.example", "origin_reflection"},
		{"https://" + targetHost + ".evil.example", "partial_origin_match"},
		{"https://trusted-sub." + targetHost, "trusted_subdomain"},
	}
	for _, pr := range probes {
		headers := map[string]string{"Origin": pr.origin}
		if pr.origin == "null" {
			headers["Origin"] = "null"
		}
		rr, err := r.probeWithHeaders(ctx, target, "", headers)
		if err != nil {
			continue
		}
		if !corsSignal(rr.Response.Headers, pr.origin, pr.signal) {
			continue
		}
		p := defaultPayload("cors", pr.signal, pr.origin, pr.signal)
		if len(payloadsForClass(target.Payloads.Payloads, "cors")) > 0 {
			p = payloadsForClass(target.Payloads.Payloads, "cors")[0]
		}
		f := r.verifyAndBuild(ctx, "cors", target, p, baseline, rr, pr.signal, false, false, "", "")
		r.recordFinding(&out, f, "cors", pr.signal)
	}
	// withCredentials + wildcard
	wcHeaders := map[string]string{"Origin": "https://evil.example"}
	rr, err := r.probeWithHeaders(ctx, target, "", wcHeaders)
	if err == nil && corsWildcardCredentials(rr.Response.Headers) {
		p := defaultPayload("cors", "wildcard_credentials", "*", "wildcard_credentials")
		f := r.verifyAndBuild(ctx, "cors", target, p, baseline, rr, "wildcard_credentials", false, false, "", "")
		r.recordFinding(&out, f, "cors", "wildcard_credentials")
	}
	return out
}

func corsSignal(headers map[string]string, origin, signal string) bool {
	acao := headerValue(headers, "Access-Control-Allow-Origin")
	switch signal {
	case "null_origin":
		return acao == "null" || strings.EqualFold(acao, "null")
	case "origin_reflection":
		acac := headerValue(headers, "Access-Control-Allow-Credentials")
		hasCredentials := strings.EqualFold(acac, "true")
		return hasCredentials && (acao == origin || strings.Contains(acao, "evil.example"))
	case "partial_origin_match":
		return acao == origin || strings.Contains(acao, "evil.example")
	case "trusted_subdomain":
		return acao == origin || (acao != "" && acao != "*" && strings.Contains(acao, "trusted-sub"))
	default:
		return acao != "" && acao != "https://benign.example"
	}
}

func corsWildcardCredentials(headers map[string]string) bool {
	acao := headerValue(headers, "Access-Control-Allow-Origin")
	acac := headerValue(headers, "Access-Control-Allow-Credentials")
	return acao == "*" && strings.EqualFold(acac, "true")
}

func headerValue(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}
