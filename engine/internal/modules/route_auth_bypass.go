package modules

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/urlutil"
	"github.com/akha-security/akca/engine/internal/verification"
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
	if method == "" || (method != "GET" && method != "HEAD" && method != "OPTIONS") {
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

	// Bind a bypass to the exact private resource, not any different public page.
	owner, ownerErr := r.client.Do(ctx, method, targetURL, nil, nil)
	canary := r.privateCanary("route_auth_bypass", target)
	ownerOK := ownerErr == nil && successfulResourceResponse(owner.Response) &&
		requestCarriesAuthentication(owner.Request.Headers) && privateAuthResourceEvidence(owner.Response.Body) &&
		!anonymousExposesSameResource(baselineRR.Response, owner.Response)
	if !ownerOK && canary == "" {
		r.emitDiscovery("route_auth_bypass", target, "resource_reference_missing", "No authenticated private-resource reference or configured private canary; status differences cannot prove an authentication bypass")
		return nil
	}
	// Step 2: Negative Control (Catch-All / Soft 404 Guard)
	// Probe a guaranteed non-existent sibling route to ensure server doesn't blindly return 200 for everything.
	nonexistentURL := buildNonexistentProbeURL(u)
	if nonexistentURL == "" || !r.scope.IsInScope(nonexistentURL) {
		return nil
	}
	negRR, negErr := client.DoWithoutSession(ctx, method, nonexistentURL, nil, nil)
	if negErr != nil || !routeNegativeControlOK(negRR.Response) {
		r.emitSkip("route_auth_bypass", target, "missing or successful nonexistent-route control")
		return nil
	}

	// Step 2b: Root Homepage Control - Ensure path normalization doesn't just route back to the public homepage
	rootURL := u.Scheme + "://" + u.Host + "/"
	var rootRR httpclient.RequestResponse
	var rootErr error
	if r.scope.IsInScope(rootURL) {
		rootRR, rootErr = client.DoWithoutSession(ctx, http.MethodGet, rootURL, nil, nil)
	} else {
		return nil
	}
	if rootErr != nil || rootRR.Response.StatusCode == 0 || rootRR.Response.StatusCode >= 500 {
		r.emitSkip("route_auth_bypass", target, "public-root control unavailable")
		return nil
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

		// A response difference is only a candidate, never private-resource proof.
		if !isRouteBypassSuccessful(probeRR.Response, baselineRR.Response) {
			continue
		}

		// Must not be a normalization fallback to the public homepage
		if rootRR.Response.StatusCode == http.StatusOK && len(rootRR.Response.Body) > 0 {
			if probeRR.Response.Body == rootRR.Response.Body || bodiesSimilar(probeRR.Response.Body, rootRR.Response.Body) {
				continue
			}
		}

		bound := ownerOK && sameBrokenAuthResource(owner.Response.Body, probeRR.Response.Body)
		canaryBound := canary != "" && !strings.Contains(baselineRR.Response.Body, canary) &&
			!strings.Contains(rootRR.Response.Body, canary) && !strings.Contains(negRR.Response.Body, canary) &&
			strings.Contains(probeRR.Response.Body, canary)
		bound = bound || canaryBound
		if !bound {
			r.emitDiscovery("route_auth_bypass", target, v.technique, "Alternate route observed without private-resource identity proof")
			continue
		}
		if sameBrokenAuthResource(negRR.Response.Body, probeRR.Response.Body) ||
			sameBrokenAuthResource(rootRR.Response.Body, probeRR.Response.Body) {
			continue
		}
		// A proxy header must select the protected route, rather than trigger a
		// generic response for every header value (or simply be ignored).
		var headerControl httpclient.RequestResponse
		if v.technique == "x_original_url_header" || v.technique == "x_rewrite_url_header" {
			missing, _ := url.Parse(nonexistentURL)
			controlHeaders := make(map[string]string, len(v.headers))
			for name := range v.headers {
				controlHeaders[name] = missing.RequestURI()
			}
			var controlErr error
			headerControl, controlErr = client.DoWithoutSession(ctx, method, v.url, nil, controlHeaders)
			if controlErr != nil || !routeNegativeControlOK(headerControl.Response) ||
				sameBrokenAuthResource(headerControl.Response.Body, probeRR.Response.Body) ||
				(canaryBound && strings.Contains(headerControl.Response.Body, canary)) {
				continue
			}
		}
		// Dual Replay Confirmation: Replay probe twice to ensure it's not a flaky network/race response
		replay1, err1 := client.DoWithoutSession(ctx, method, v.url, nil, v.headers)
		if err1 != nil || !routeReplayMatches(replay1.Response, probeRR.Response, baselineRR.Response, canary, canaryBound) {
			continue
		}
		replay2, err2 := client.DoWithoutSession(ctx, method, v.url, nil, v.headers)
		if err2 != nil || !routeReplayMatches(replay2.Response, probeRR.Response, baselineRR.Response, canary, canaryBound) {
			continue
		}

		// Ensure body content is stable across replays
		if replay1.Response.Body != replay2.Response.Body && !sameBrokenAuthResource(replay1.Response.Body, replay2.Response.Body) {
			continue
		}
		baselineAfter, baselineErr := client.DoWithoutSession(ctx, method, targetURL, nil, nil)
		if baselineErr != nil || baselineAfter.Response.StatusCode != baselineRR.Response.StatusCode ||
			!sameResourceFingerprint(baselineAfter.Response.Body, baselineRR.Response.Body) {
			continue
		}
		var ownerAfter httpclient.RequestResponse
		if ownerOK {
			var ownerAfterErr error
			ownerAfter, ownerAfterErr = r.client.Do(ctx, method, targetURL, nil, nil)
			if ownerAfterErr != nil || !requestCarriesAuthentication(ownerAfter.Request.Headers) ||
				!successfulResourceResponse(ownerAfter.Response) || !sameBrokenAuthResource(owner.Response.Body, ownerAfter.Response.Body) {
				continue
			}
		}

		p := defaultPayload("route_auth_bypass", v.technique, v.url, v.technique)
		f := r.verifyAndBuildWithCandidate(ctx, "route_auth_bypass", target, p, baselineRR, probeRR,
			v.technique, false, false, "", "", func(c *verification.Candidate) {
				c.RequestedProofType = verification.ProofDifferentialReplay
				c.NegativeControlSet = true
				c.NegativeControlOK = true
				c.TypedReplayHits = []bool{true, true, true}
				c.PrivateResourceCanary = ""
				if canaryBound {
					c.PrivateResourceCanary = canary
				}
				c.StabilityRuns = []verification.ResponseSnapshot{snapshot(probeRR.Response), snapshot(replay1.Response), snapshot(replay2.Response)}
				c.Observations = append(c.Observations, r.observation("route_auth_bypass", target, verification.RoleNegativeControl, 1, negRR), r.observation("route_auth_bypass", target, verification.RoleNegativeControl, 2, rootRR), r.observation("route_auth_bypass", target, verification.RolePositiveReplay, 2, replay1), r.observation("route_auth_bypass", target, verification.RolePositiveReplay, 3, replay2))
				c.Observations = append(c.Observations, r.observation("route_auth_bypass", target, verification.RoleBaselineReplay, 2, baselineAfter))
				if ownerOK {
					c.Observations = append(c.Observations, r.identityObservation("route_auth_bypass", target, verification.RoleIdentityA, 1, "authenticated", owner), r.identityObservation("route_auth_bypass", target, verification.RoleIdentityA, 2, "authenticated", ownerAfter))
				}
				if headerControl.Request.URL != "" {
					c.Observations = append(c.Observations, r.observation("route_auth_bypass", target, verification.RoleNegativeControl, 3, headerControl))
				}
			})
		if f == nil {
			continue
		}

		if f != nil {
			proofStep := func(role verification.ObservationRole, identity string, rr httpclient.RequestResponse) ReplayStep {
				return ReplayStep{Role: role, IdentityID: identity, Request: rr.Request,
					ExpectedNormalizedHash: r.observation("route_auth_bypass", target, role, 1, rr).NormalizedHash}
			}
			f.Title = "Route Authentication Bypass: Proxy/Normalization Discrepancy (" + v.technique + ")"
			binding := "the authenticated private-resource response"
			if canaryBound {
				binding = "the explicitly configured private-resource canary"
			}
			f.Description = fmt.Sprintf("The canonical endpoint (%s) returned HTTP %d anonymously. Three independent anonymous requests using %s reproduced %s. Nonexistent-route and public-root controls did not expose that resource.", targetURL, baselineRR.Response.StatusCode, v.technique, binding)
			f.Severity = "High"
			f.Evidence.ReplayPlan = append(f.Evidence.ReplayPlan, proofStep(verification.RoleNegativeControl, "", negRR), proofStep(verification.RoleNegativeControl, "", rootRR))
			if ownerOK {
				f.Evidence.ResourceReference = &owner.Response
				f.Evidence.ReplayPlan = append(f.Evidence.ReplayPlan, proofStep(verification.RoleIdentityA, "authenticated", owner))
			}
			if headerControl.Request.URL != "" {
				f.Evidence.ReplayPlan = append(f.Evidence.ReplayPlan, proofStep(verification.RoleNegativeControl, "", headerControl))
			}
		}
		r.recordFinding(ctx, &out, f, "route_auth_bypass", v.technique)
		// One solid, confirmed finding per endpoint is sufficient
		break
	}

	return out
}

func routeNegativeControlOK(response httpclient.ResponseRecord) bool {
	return response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden ||
		response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusGone
}

func routeReplayMatches(replay, probe, baseline httpclient.ResponseRecord, canary string, canaryBound bool) bool {
	if replay.Redirected || !isRouteBypassSuccessful(replay, baseline) || !sameBrokenAuthResource(probe.Body, replay.Body) {
		return false
	}
	return !canaryBound || strings.Contains(replay.Body, canary)
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

	// 5. Header Overrides (X-Original-URL / X-Rewrite-URL / Method Override)
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
	out = append(out, routeVariant{
		url:       u.String(),
		headers:   map[string]string{"X-HTTP-Method-Override": "GET"},
		technique: "http_method_override_header",
	})

	// 6. URL-Encoded Slash Variant (/admin%2Fusers)
	if lastSlash := strings.LastIndex(trimmedPath, "/"); lastSlash > 0 {
		encPath := trimmedPath[:lastSlash] + "%2F" + trimmedPath[lastSlash+1:]
		out = append(out, routeVariant{
			url:       buildMutatedURL(u, encPath),
			technique: "url_encoded_slash",
		})
	}

	// 7. Case Variation (e.g. /Admin/users)
	if len(path) > 1 {
		firstLetter := strings.ToUpper(string(path[1]))
		casedPath := "/" + firstLetter + path[2:]
		if casedPath != path {
			out = append(out, routeVariant{
				url:       buildMutatedURL(u, casedPath),
				technique: "case_variation",
			})
		}
	}

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
