package modules

import (
	"context"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scriptsurface"
)

func (r *Runner) runScriptSource(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("script_source", target); !ok {
		r.emitSkip("script_source", target, reason)
		return nil
	}
	pageRR, err := r.cachedEmptyProbe(ctx, target)
	if err != nil || pageRR.Response.Body == "" {
		return nil
	}
	u, err := url.Parse(target.EndpointURL)
	if err != nil {
		return nil
	}
	pageHost := u.Hostname()
	baseline := httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: 404, Body: "missing"}}
	var out []ModuleFinding
	seen := map[string]struct{}{}
	for _, res := range scriptsurface.ExtractFromHTML(pageRR.Response.Body, target.EndpointURL) {
		if !scriptsurface.IsThirdParty(res.Domain, pageHost) {
			continue
		}
		if _, ok := seen[res.URL]; ok {
			continue
		}
		seen[res.URL] = struct{}{}
		if ctx.Err() != nil {
			break
		}
		rr, err := r.client.Do(ctx, "GET", res.URL, nil, nil)
		if err != nil {
			continue
		}
		ok, signal := scriptsurface.AnalyzeResponse(rr.Response.StatusCode, rr.Response.Body)
		if !ok {
			continue
		}
		p := defaultPayload("script_source", res.Kind+"_"+signal, res.URL, signal)
		f := r.verifyAndBuild(ctx, "script_source", target, p, baseline, rr, signal, false, false, "", "")
		if f == nil {
			continue
		}
		f.Title = "Controllable external " + res.Kind + " (" + signal + ")"
		f.Description = res.URL + " referenced from page; " + signal
		r.recordFinding(ctx, &out, f, "script_source", signal)
		if len(out) >= 3 {
			break
		}
	}

	// Check Dependency Confusion for extracted scoped packages
	for _, res := range scriptsurface.ExtractFromHTML(pageRR.Response.Body, target.EndpointURL) {
		if res.Kind == "package" && strings.HasPrefix(res.URL, "@") {
			pkgURL := "https://registry.npmjs.org/" + res.URL
			if _, ok := seen[pkgURL]; ok {
				continue
			}
			seen[pkgURL] = struct{}{}
			rr, err := r.client.Do(ctx, "GET", pkgURL, nil, nil)
			if err != nil {
				continue
			}
			if ok, signal := scriptsurface.CheckDependencyConfusion(rr.Response.StatusCode, rr.Response.Body); ok {
				p := defaultPayload("script_source", "dependency_confusion", res.URL, signal)
				f := r.verifyAndBuild(ctx, "script_source", target, p, baseline, rr, signal, false, false, "", "")
				if f != nil {
					f.Title = "Dependency Confusion Risk (Unregistered Scoped Package: " + res.URL + ")"
					f.Severity = "critical"
					f.Description = "Internal package '" + res.URL + "' was referenced in client-side code but is unregistered on the public NPM registry."
					r.recordFinding(ctx, &out, f, "script_source", signal)
				}
			}
		}
	}

	return out
}
