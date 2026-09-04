package modules

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

var proxyConfusionTransforms = []struct {
	prefix string
	suffix string
	desc   string
}{
	{prefix: "/..;/", suffix: "", desc: "Tomcat path parameter matrix bypass (/..;/)"},
	{prefix: "/%2e%2e/", suffix: "", desc: "URL-encoded dot-dot slash bypass (/%2e%2e/)"},
	{prefix: "/.;/", suffix: "", desc: "Matrix parameter single dot (/.;/)"},
	{prefix: "/%20/", suffix: "", desc: "URL-encoded space prefix"},
	{prefix: "", suffix: ";foo=bar", desc: "Matrix parameter suffix (;foo=bar)"},
}

func (r *Runner) runProxyPathConfusion(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("proxy_path_confusion", target); !ok {
		r.emitSkip("proxy_path_confusion", target, reason)
		return nil
	}

	u, err := url.Parse(target.EndpointURL)
	if err != nil || u.Path == "" || u.Path == "/" {
		return nil
	}
	origin := u.Scheme + "://" + u.Host

	// Only test on 401/403 or restricted endpoints to find authentication/authorization bypass
	baselineRR, err := r.cachedEmptyProbe(ctx, target)
	if err != nil || (baselineRR.Response.StatusCode != 401 && baselineRR.Response.StatusCode != 403) {
		return nil
	}

	var out []ModuleFinding
	for _, tr := range proxyConfusionTransforms {
		if ctx.Err() != nil {
			break
		}

		transformedPath := tr.prefix + strings.TrimPrefix(u.Path, "/") + tr.suffix
		if strings.HasPrefix(tr.prefix, "/") && strings.HasPrefix(u.Path, "/") {
			transformedPath = tr.prefix + strings.TrimPrefix(u.Path, "/") + tr.suffix
		}

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

		// Re-verify that baseline is STILL 401/403
		reBase, bErr := r.client.Do(ctx, target.Method, target.EndpointURL, nil, nil)
		if bErr != nil || (reBase.Response.StatusCode != 401 && reBase.Response.StatusCode != 403) {
			continue
		}
		replay, replayErr := r.client.Do(ctx, target.Method, transformedURL, nil, nil)
		if replayErr != nil || replay.Response.StatusCode != 200 || isLoginOrErrorBody(replay.Response.Body) ||
			!sameResourceFingerprint(rr.Response.Body, replay.Response.Body) {
			continue
		}

		signal := "proxy_path_confusion_bypass"
		p := defaultPayload("proxy_path_confusion", signal, transformedPath, signal)
		f := r.verifyAndBuild(ctx, "proxy_path_confusion", target, p, baselineRR, rr, signal, false, false, "", "")
		if f != nil {
			f.Severity = "high"
			f.Title = fmt.Sprintf("Reverse Proxy Path Confusion Authorization Bypass (%s)", tr.desc)
			f.Description = fmt.Sprintf("Reverse proxy ACL restriction on '%s' (Status: %d) was bypassed via path confusion sequence '%s' (Status: 200).", target.EndpointURL, baselineRR.Response.StatusCode, transformedPath)
			r.recordFinding(ctx, &out, f, "proxy_path_confusion", signal)
			return out
		}
	}

	return out
}
