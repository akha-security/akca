package modules

import (
	"context"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

func (r *Runner) runOpenRedirect(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("open_redirect", target); !ok {
		r.emitSkip("open_redirect", target, reason)
		return nil
	}
	if target.Parameter != "" && !isLikelyOpenRedirectParam(target.Parameter) {
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
		{"///evil.example/akca", "triple_slash_protocol_relative"},
		{"/\\evil.example", "path_confusion"},
		{"https:evil.example", "scheme_relative_colon"},
		{"https:/evil.example", "single_slash_scheme"},
		{"@evil.example", "userinfo_confusion"},
		{"javascript:alert(1)", "javascript_uri"},
		{"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "data_uri"},
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
		r.recordFinding(ctx, &out, f, "open_redirect", pr.signal)
	}
	return out
}

func openRedirectSignal(rr httpclient.RequestResponse, value string) bool {
	// A Location query value is not a navigation destination. Inspect the
	// authority without decoding nested query parameters or userinfo.
	status := rr.Response.StatusCode
	if status != 301 && status != 302 && status != 303 && status != 307 && status != 308 {
		return false
	}
	return redirectDestinationIsCanary(headerValue(rr.Response.Headers, "Location"))
}

func redirectDestinationIsCanary(location string) bool {
	location = strings.TrimSpace(location)
	if strings.ContainsAny(location, "\r\n\x00") {
		return false
	}
	location = strings.ReplaceAll(location, `\`, "/")
	if strings.HasPrefix(location, "//") {
		location = "https://" + strings.TrimLeft(location, "/")
	}
	u, err := url.Parse(location)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	return strings.EqualFold(strings.TrimSuffix(u.Hostname(), "."), "evil.example")
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
		r.recordFinding(ctx, &out, f, "host_header", "host_injection")
	}
	return out
}

func hostHeaderSignal(body, baseline string) bool {
	return strings.Contains(strings.ToLower(body), "evil.akca.local") && body != baseline
}

func isLikelyOpenRedirectParam(param string) bool {
	p := strings.ToLower(strings.TrimSpace(param))
	if p == "" {
		return true
	}
	switch p {
	case "page", "p", "pg", "limit", "offset", "size", "per_page", "perpage",
		"sort", "order", "dir", "direction", "by", "orderby",
		"v", "ver", "version", "_", "t", "ts", "timestamp", "cb", "cache", "nocache",
		"format", "lang", "locale", "id", "item_id", "user_id", "post_id", "product_id",
		"price", "qty", "count", "num", "min", "max", "width", "height":
		return false
	}
	redirectKeywords := []string{
		"redirect", "url", "uri", "link", "next", "return", "target", "dest",
		"destination", "r", "goto", "go", "to", "out", "view", "forward", "ref",
		"callback", "continue", "site", "domain", "host", "path", "checkout",
		"success", "cancel", "auth", "login", "oauth", "service", "src",
	}
	for _, kw := range redirectKeywords {
		if strings.Contains(p, kw) {
			return true
		}
	}
	if len(p) <= 2 {
		return true
	}
	return false
}
