package modules

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/verification"
)

type sessionlessHTTPDoer interface {
	DoWithoutSession(ctx context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error)
}

func (r *Runner) runBrokenAuth(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("broken_auth", target); !ok {
		r.emitSkip("broken_auth", target, reason)
		return nil
	}
	var out []ModuleFinding
	client, ok := r.client.(sessionlessHTTPDoer)
	if !ok {
		r.emitSkip("broken_auth", target, "HTTP client cannot create an anonymous control request")
		return nil
	}
	baseline, err := r.cachedEmptyProbe(ctx, target)
	if err != nil {
		return nil
	}
	rr, err := client.DoWithoutSession(ctx, baseline.Request.Method, baseline.Request.URL, []byte(baseline.Request.Body), nil)
	if err != nil {
		return nil
	}
	if !brokenAuthSignal(rr.Response, baseline.Response) {
		return nil
	}
	replay, err := client.DoWithoutSession(ctx, baseline.Request.Method, baseline.Request.URL,
		[]byte(baseline.Request.Body), nil)
	if err != nil || !brokenAuthSignal(replay.Response, baseline.Response) ||
		resourceFingerprint(rr.Response.Body) != resourceFingerprint(replay.Response.Body) {
		return nil
	}
	p := defaultPayload("broken_auth", "missing_auth_access", target.EndpointURL, "missing_auth_access")
	f := r.verifyAndBuildWithCandidate(ctx, "broken_auth", target, p, baseline, rr,
		"missing_auth_access", false, false, "", "", func(candidate *verification.Candidate) {
			candidate.RequestedProofType = verification.ProofAnonymousAccess
			// Anonymous access is proven by equivalence with the authenticated
			// resource. A matching body is therefore expected evidence, not a
			// reason for the generic differential guard to suppress the result.
			candidate.ExpectedEquivalent = true
			candidate.Observations = append(candidate.Observations,
				r.identityObservation("broken_auth", target, verification.RoleIdentityA, 1, "authenticated", baseline),
				r.identityObservation("broken_auth", target, verification.RoleAnonymousProbe, 1, "anonymous", rr),
				r.identityObservation("broken_auth", target, verification.RoleAnonymousProbe, 2, "anonymous", replay),
			)
		})
	r.recordFinding(&out, f, "broken_auth", "missing_auth_access")
	return out
}

func brokenAuthSignal(probe, baseline httpclient.ResponseRecord) bool {
	if baseline.StatusCode < 200 || baseline.StatusCode >= 400 || probe.StatusCode < 200 || probe.StatusCode >= 400 {
		return false
	}
	probeLower := strings.ToLower(probe.Body)
	baseLower := strings.ToLower(baseline.Body)
	if authDeniedBody(probeLower) || authDeniedBody(baseLower) {
		return false
	}
	sensitive := []string{"dashboard", "admin", "profile", "account", "access_token", "session", "billing", "orders"}
	for _, kw := range sensitive {
		if strings.Contains(baseLower, kw) && strings.Contains(probeLower, kw) {
			return true
		}
	}
	return len(strings.TrimSpace(baseline.Body)) >= 80 && bodyDiffRatio(normalizeVolatileFields(baseline.Body), normalizeVolatileFields(probe.Body)) < 0.08
}

func authDeniedBody(lower string) bool {
	for _, marker := range []string{"unauthorized", "forbidden", "please log in", "please login", "sign in", "authentication required", "invalid session"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func (r *Runner) runCSRF(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("csrf", target); !ok {
		r.emitSkip("csrf", target, reason)
		return nil
	}
	return r.runClassicCSRF(ctx, target)
}

func (r *Runner) runClassicCSRF(ctx context.Context, target ScanTarget) []ModuleFinding {
	var out []ModuleFinding
	method := strings.ToUpper(strings.TrimSpace(target.Method))
	if method != http.MethodPost && method != http.MethodPut && method != http.MethodPatch && method != http.MethodDelete {
		r.emitSkip("csrf", target, "CSRF requires a state-changing HTTP method")
		return nil
	}
	if !hasAmbientAuthentication(r.cfg) || strings.TrimSpace(target.BodyTemplate) == "" {
		r.emitSkip("csrf", target, "CSRF proof requires an authenticated session and the original request body")
		return nil
	}
	missingBody, invalidBody, contentType, ok := csrfBodyVariants(target.BodyTemplate, target.Profile.ContentType)
	if !ok {
		r.emitSkip("csrf", target, "no anti-CSRF token was identified in the original request body")
		return nil
	}
	headers := map[string]string{
		"Content-Type": contentType, "Origin": "https://akca.invalid", "Referer": "https://akca.invalid/csrf-proof",
	}
	baseline, err := r.client.Do(ctx, method, target.EndpointURL, []byte(target.BodyTemplate), map[string]string{"Content-Type": contentType})
	if err != nil || baseline.Response.StatusCode >= 400 {
		return nil
	}
	missing, err := r.client.Do(ctx, method, target.EndpointURL, []byte(missingBody), headers)
	if err != nil || !csrfAccepted(missing.Response) {
		return nil
	}
	invalid, err := r.client.Do(ctx, method, target.EndpointURL, []byte(invalidBody), headers)
	if err != nil || !csrfRejected(invalid.Response) {
		return nil
	}
	if bodyDiffRatio(normalizeVolatileFields(baseline.Response.Body), normalizeVolatileFields(missing.Response.Body)) > 0.25 {
		return nil
	}
	p := defaultPayload("csrf", "missing_token", target.EndpointURL, "missing_csrf_token")
	f := r.verifyAndBuildWithCandidate(ctx, "csrf", target, p, invalid, missing,
		"missing_csrf_token", false, false, "", "", func(candidate *verification.Candidate) {
			candidate.RequestedProofType = verification.ProofRequestPolicy
			candidate.NegativeControlSet = true
			candidate.NegativeControlOK = true
			candidate.Observations = append(candidate.Observations,
				r.observation("csrf", target, verification.RoleBaselineReplay, 1, baseline),
				r.observation("csrf", target, verification.RoleNegativeControl, 1, invalid),
			)
		})
	if f != nil {
		f.Description = "The original authenticated request succeeded, the same cross-site request without the anti-CSRF token succeeded, and an invalid-token negative control was rejected."
		f.Evidence.ResponseMarkers = append(f.Evidence.ResponseMarkers, "invalid_token_control_rejected")
	}
	r.recordFinding(&out, f, "csrf", "missing_csrf_token")
	return out
}

func hasAmbientAuthentication(cfg config.ScanConfig) bool {
	if len(cfg.SessionCookies) > 0 {
		return true
	}
	for name := range cfg.CustomHeaders {
		if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "X-API-Key") || strings.EqualFold(name, "X-Auth-Token") {
			return true
		}
	}
	return false
}

func csrfBodyVariants(template, contentType string) (missing, invalid, resolvedContentType string, ok bool) {
	trimmed := strings.TrimSpace(template)
	if strings.Contains(strings.ToLower(contentType), "json") || strings.HasPrefix(trimmed, "{") {
		var object map[string]interface{}
		if json.Unmarshal([]byte(template), &object) != nil {
			return "", "", "", false
		}
		key := csrfTokenKey(object)
		if key == "" {
			return "", "", "", false
		}
		delete(object, key)
		missingRaw, _ := json.Marshal(object)
		object[key] = "akca-invalid-csrf-token"
		invalidRaw, _ := json.Marshal(object)
		return string(missingRaw), string(invalidRaw), "application/json", true
	}
	values, err := url.ParseQuery(template)
	if err != nil {
		return "", "", "", false
	}
	key := csrfTokenFormKey(values)
	if key == "" {
		return "", "", "", false
	}
	values.Del(key)
	missing = values.Encode()
	values.Set(key, "akca-invalid-csrf-token")
	return missing, values.Encode(), "application/x-www-form-urlencoded", true
}

func csrfTokenKey(object map[string]interface{}) string {
	for key := range object {
		if isCSRFTokenName(key) {
			return key
		}
	}
	return ""
}

func csrfTokenFormKey(values url.Values) string {
	for key := range values {
		if isCSRFTokenName(key) {
			return key
		}
	}
	return ""
}

func isCSRFTokenName(name string) bool {
	name = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(name, "-", "_"), ".", "_"))
	return strings.Contains(name, "csrf") || strings.Contains(name, "xsrf") ||
		strings.Contains(name, "request_verification_token") || strings.Contains(name, "anti_forgery")
}

func csrfAccepted(response httpclient.ResponseRecord) bool {
	if response.StatusCode < 200 || response.StatusCode >= 400 {
		return false
	}
	lower := strings.ToLower(response.Body)
	if strings.Contains(lower, "csrf") || strings.Contains(lower, "forbidden") || strings.Contains(lower, "invalid token") {
		return false
	}
	return true
}

func csrfRejected(response httpclient.ResponseRecord) bool {
	if response.StatusCode == http.StatusBadRequest || response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusUnprocessableEntity {
		return true
	}
	lower := strings.ToLower(response.Body)
	return strings.Contains(lower, "csrf") && (strings.Contains(lower, "invalid") || strings.Contains(lower, "forbidden") || strings.Contains(lower, "mismatch"))
}

func (r *Runner) runWordPressFuzz(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("wordpress_fuzz", target); !ok {
		r.emitSkip("wordpress_fuzz", target, reason)
		return nil
	}
	base := wordpressBase(target.EndpointURL)
	if base == "" {
		return nil
	}
	var out []ModuleFinding
	baseline, err := r.client.Do(ctx, http.MethodGet, base+"/", nil, nil)
	if err != nil {
		return nil
	}
	paths := []struct{ path, signal string }{
		{"/wp-json/wp/v2/users", "user_enum"},
		{"/xmlrpc.php", "xmlrpc_enabled"},
		{"/wp-login.php", "login_exposed"},
		{"/readme.html", "version_disclosure"},
	}
	for _, pr := range paths {
		rr, err := r.client.Do(ctx, http.MethodGet, base+pr.path, nil, nil)
		if err != nil {
			continue
		}
		if !wordpressSignal(rr.Response.StatusCode, rr.Response.Body, pr.signal) {
			continue
		}
		p := defaultPayload("wordpress_fuzz", pr.signal, base+pr.path, pr.signal)
		f := r.verifyAndBuild(ctx, "wordpress_fuzz", target, p, baseline, rr, pr.signal, false, false, "", "")
		if f != nil {
			switch pr.signal {
			case "login_exposed", "version_disclosure", "xmlrpc_enabled":
				f.Severity = "info"
			case "user_enum":
				f.Severity = "low"
			}
		}
		r.recordFinding(&out, f, "wordpress_fuzz", pr.signal)
	}
	return out
}

func wordpressBase(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if idx := strings.Index(raw, "/wp-"); idx > 0 {
		return strings.TrimRight(raw[:idx], "/")
	}
	if strings.Contains(strings.ToLower(raw), "wordpress") {
		if i := strings.Index(raw, "://"); i >= 0 {
			rest := raw[i+3:]
			if slash := strings.Index(rest, "/"); slash >= 0 {
				return raw[:i+3+slash]
			}
		}
		return strings.TrimRight(raw, "/")
	}
	return ""
}

func wordpressSignal(status int, body, signal string) bool {
	if status == 404 || status == 403 {
		return false
	}
	lower := strings.ToLower(body)
	switch signal {
	case "user_enum":
		return status == 200 && strings.Contains(lower, `"slug"`)
	case "xmlrpc_enabled":
		return status == 200 && strings.Contains(lower, "xml-rpc")
	case "login_exposed":
		return status == 200 && strings.Contains(lower, "wp-login")
	case "version_disclosure":
		return status == 200 && strings.Contains(lower, "wordpress")
	default:
		return status >= 200 && status < 400
	}
}
