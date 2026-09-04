package modules

import (
	"context"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

type frameworkDebugProbe struct {
	path        string
	kind        string
	title       string
	severity    string
	fingerprint string
	desc        string
}

var frameworkDebugProbes = []frameworkDebugProbe{
	// Flask / Werkzeug Debugger
	{
		path:        "/console",
		kind:        "werkzeug_debugger",
		title:       "Flask/Werkzeug Interactive Debug Console Exposed",
		severity:    "critical",
		fingerprint: "Werkzeug powered",
		desc:        "Interactive Werkzeug debugger console is exposed, enabling arbitrary Python code execution if PIN is known or unconfigured.",
	},
	{
		path:        "/__debugger__",
		kind:        "werkzeug_debugger",
		title:       "Flask/Werkzeug Interactive Debugger Exposed",
		severity:    "critical",
		fingerprint: "Werkzeug powered",
		desc:        "Interactive Werkzeug debugger endpoint is exposed.",
	},
	// Laravel Ignition & DevTools
	{
		path:        "/_ignition/health-check",
		kind:        "laravel_ignition",
		title:       "Laravel Ignition Debugger Health-Check Exposed",
		severity:    "high",
		fingerprint: "can_execute_commands",
		desc:        "Laravel Ignition error page handler is exposed. If solution execution is enabled, this allows unauthenticated remote code execution.",
	},
	{
		path:        "/_ignition/execute-solution",
		kind:        "laravel_ignition_rce",
		title:       "Laravel Ignition Execute-Solution RCE Exposed",
		severity:    "critical",
		fingerprint: "solution",
		desc:        "Laravel Ignition execute-solution endpoint is accessible.",
	},
	{
		path:        "/telescope/requests",
		kind:        "laravel_telescope",
		title:       "Laravel Telescope DevTool Dashboard Exposed",
		severity:    "high",
		fingerprint: "Telescope",
		desc:        "Laravel Telescope debug assistant is accessible, exposing sensitive requests, database queries, and credentials.",
	},
	{
		path:        "/horizon/dashboard",
		kind:        "laravel_horizon",
		title:       "Laravel Horizon Queue Dashboard Exposed",
		severity:    "medium",
		fingerprint: "Horizon",
		desc:        "Laravel Horizon queue dashboard is publicly accessible.",
	},
	// Django Debug Toolbar
	{
		path:        "/__debug__/render_panel/",
		kind:        "django_debug_toolbar",
		title:       "Django Debug Toolbar Exposed",
		severity:    "high",
		fingerprint: "djdt",
		desc:        "Django Debug Toolbar is enabled on production, leaking internal SQL queries, templates, cache entries, and settings.",
	},
	// FastAPI / Swagger / ReDoc
	{
		path:        "/docs",
		kind:        "fastapi_swagger_docs",
		title:       "FastAPI Interactive Swagger Documentation Exposed",
		severity:    "info",
		fingerprint: "swagger-ui",
		desc:        "Interactive Swagger UI is publicly accessible, disclosing internal API endpoints, parameters, and schemas.",
	},
	{
		path:        "/redoc",
		kind:        "fastapi_redoc",
		title:       "FastAPI ReDoc Documentation Exposed",
		severity:    "info",
		fingerprint: "redoc",
		desc:        "ReDoc API documentation is publicly accessible.",
	},
	// Rails Debug & Info Exposure
	{
		path:        "/rails/info/routes",
		kind:        "rails_routes_exposure",
		title:       "Ruby on Rails Internal Route Table Exposed",
		severity:    "high",
		fingerprint: "Routes match in priority",
		desc:        "Ruby on Rails internal routing table is exposed, disclosing private controllers, admin routes, and parameters.",
	},
	{
		path:        "/rails/info/properties",
		kind:        "rails_properties_exposure",
		title:       "Ruby on Rails Environment Properties Exposed",
		severity:    "high",
		fingerprint: "Ruby version",
		desc:        "Ruby on Rails environment properties and gem versions are publicly accessible.",
	},
	{
		path:        "/rails/conductor/action_mailbox/inbound_emails",
		kind:        "rails_action_mailbox",
		title:       "Rails Action Mailbox Conductor Exposed",
		severity:    "high",
		fingerprint: "Action Mailbox",
		desc:        "Rails Action Mailbox development conductor is accessible, allowing unauthenticated inbound email injection.",
	},
}

func (r *Runner) runFrameworkDebug(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("framework_debug", target); !ok {
		r.emitSkip("framework_debug", target, reason)
		return nil
	}

	u, err := url.Parse(target.EndpointURL)
	if err != nil {
		return nil
	}
	origin := u.Scheme + "://" + u.Host

	// Wildcard / SPA check
	wildcardURL := origin + "/akca-debug-check-" + randomProbeToken()
	wRR, err := r.client.Do(ctx, "GET", wildcardURL, nil, nil)
	wildcard200 := (err == nil && wRR.Response.StatusCode == 200 && len(wRR.Response.Body) > 100)

	baseline, baselineErr := r.cachedEmptyProbe(ctx, target)
	if baselineErr != nil {
		baseline = httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: 404, Body: "not found"}}
	}

	var out []ModuleFinding
	for _, pr := range frameworkDebugProbes {
		if ctx.Err() != nil {
			break
		}
		probeURL := origin + pr.path
		if !r.scope.IsInScope(probeURL) {
			continue
		}

		rr, err := r.client.Do(ctx, "GET", probeURL, nil, nil)
		if err != nil || rr.Response.StatusCode != 200 {
			continue
		}

		body := rr.Response.Body
		if wildcard200 && bodiesSimilar(body, wRR.Response.Body) {
			// SPA catch-all returning same 200 body
			continue
		}

		if strings.Contains(body, pr.fingerprint) {
			p := defaultPayload("framework_debug", pr.kind, pr.path, pr.kind)
			f := r.verifyAndBuild(ctx, "framework_debug", target, p, baseline, rr, pr.kind, false, false, "", "")
			if f != nil {
				f.Severity = pr.severity
				f.Title = pr.title
				f.Description = pr.desc
				r.recordFinding(ctx, &out, f, "framework_debug", pr.kind)
			}
		}
	}

	return out
}

func frameworkDebugSignalConfirmed(signal, body string, status int) bool {
	if status != 200 || strings.TrimSpace(body) == "" {
		return false
	}
	for _, probe := range frameworkDebugProbes {
		if probe.kind == signal {
			return strings.Contains(body, probe.fingerprint)
		}
	}
	return false
}
