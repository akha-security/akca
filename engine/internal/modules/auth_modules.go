package modules

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
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
	if !hasAmbientAuthentication(r.cfg) {
		r.emitSkip("broken_auth", target, "an authenticated session is required for anonymous-access comparison")
		return nil
	}
	method := strings.ToUpper(strings.TrimSpace(target.Method))
	if method == "" {
		method = http.MethodGet
	}
	if method != http.MethodGet {
		r.emitSkip("broken_auth", target, "automatic anonymous-access proof is limited to safe GET requests")
		return nil
	}
	client, ok := r.client.(sessionlessHTTPDoer)
	if !ok {
		r.emitSkip("broken_auth", target, "HTTP client cannot create an anonymous control request")
		return nil
	}
	baseline, stable, reason := r.stableNativeBaselineForModule(ctx, "broken_auth", target)
	if !stable {
		r.emitSkip("broken_auth", target, reason)
		return nil
	}
	if !requestCarriesAuthentication(baseline.Request.Headers) {
		r.emitSkip("broken_auth", target, "authenticated baseline request did not carry session credentials")
		return nil
	}
	if !likelyProtectedResource(target.EndpointURL) || !privateAuthResourceEvidence(baseline.Response.Body) {
		r.emitSkip("broken_auth", target, "no strong protected-route and private-resource evidence")
		return nil
	}
	anonymousHeaders := withoutAuthenticationHeaders(baseline.Request.Headers)
	rr, err := client.DoWithoutSession(ctx, baseline.Request.Method, baseline.Request.URL,
		[]byte(baseline.Request.Body), anonymousHeaders)
	if err != nil {
		return nil
	}
	if !brokenAuthSignal(rr.Response, baseline.Response) {
		return nil
	}
	replay, err := client.DoWithoutSession(ctx, baseline.Request.Method, baseline.Request.URL,
		[]byte(baseline.Request.Body), anonymousHeaders)
	if err != nil || !brokenAuthSignal(replay.Response, baseline.Response) ||
		!sameBrokenAuthResource(rr.Response.Body, replay.Response.Body) {
		return nil
	}
	proofTarget := target
	proofTarget.Parameter = ""
	proofTarget.Location = ""
	p := defaultPayload("broken_auth", "missing_auth_access", target.EndpointURL, "missing_auth_access")
	f := r.verifyAndBuildWithCandidate(ctx, "broken_auth", proofTarget, p, baseline, rr,
		"missing_auth_access", false, false, "", "", func(candidate *verification.Candidate) {
			candidate.RequestedProofType = verification.ProofAnonymousAccess
			// Anonymous access is proven by equivalence with the authenticated
			// resource. A matching body is therefore expected evidence, not a
			// reason for the generic differential guard to suppress the result.
			candidate.ExpectedEquivalent = true
			candidate.Observations = append(candidate.Observations,
				r.identityObservation("broken_auth", proofTarget, verification.RoleIdentityA, 1, "authenticated", baseline),
				r.identityObservation("broken_auth", proofTarget, verification.RoleAnonymousProbe, 1, "anonymous", rr),
				r.identityObservation("broken_auth", proofTarget, verification.RoleAnonymousProbe, 2, "anonymous", replay),
			)
		})
	if f != nil {
		f.Title = "Broken Authentication: Private Resource Accessible Without Session"
		f.Description = "A stable authenticated GET response containing private account data was reproduced twice without any session credentials on a protected route."
	}
	r.recordFinding(ctx, &out, f, "broken_auth", "missing_auth_access")
	return out
}

func brokenAuthSignal(probe, baseline httpclient.ResponseRecord) bool {
	if !successfulResourceResponse(baseline) || !successfulResourceResponse(probe) {
		return false
	}
	probeLower := strings.ToLower(probe.Body)
	baseLower := strings.ToLower(baseline.Body)
	if authDeniedBody(probeLower) || authDeniedBody(baseLower) {
		return false
	}
	return privateAuthResourceEvidence(baseline.Body) && sameBrokenAuthResource(probe.Body, baseline.Body)
}

func authDeniedBody(lower string) bool {
	for _, marker := range []string{
		"unauthorized", "forbidden", "access denied", "not authorized", "authentication failed",
		"please log in", "please login", "login required", "sign in", "authentication required",
		"invalid session", "session expired", "giriş yap", "oturum aç", "yetkisiz", "erişim reddedildi",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func requestCarriesAuthentication(headers map[string]string) bool {
	for name, value := range headers {
		if strings.TrimSpace(value) == "" || value == "[REDACTED]" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "authorization", "cookie", "proxy-authorization", "x-api-key", "x-auth-token", "x-token":
			return true
		}
	}
	return false
}

func withoutAuthenticationHeaders(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers))
	for name, value := range headers {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "authorization", "cookie", "proxy-authorization", "x-api-key", "x-auth-token", "x-token":
			continue
		}
		out[name] = value
	}
	return out
}

func likelyProtectedResource(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	path := "/" + strings.Trim(strings.ToLower(parsed.Path), "/") + "/"
	for _, public := range []string{
		"/public/", "/docs/", "/swagger/", "/openapi/", "/login/", "/signin/", "/register/",
		"/health/", "/status/", "/assets/", "/static/",
	} {
		if strings.Contains(path, public) {
			return false
		}
	}
	for _, protected := range []string{
		"/admin/", "/auth/profile/", "/account/", "/accounts/", "/dashboard/", "/billing/",
		"/invoice/", "/invoices/", "/order/", "/orders/", "/settings/", "/me/",
	} {
		if strings.Contains(path, protected) {
			return true
		}
	}
	return false
}

var privateAuthEmailRE = regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b`)

func privateAuthResourceEvidence(body string) bool {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return false
	}
	var document interface{}
	if json.Unmarshal([]byte(trimmed), &document) == nil {
		strong, identity := privateJSONEvidence(document)
		return strong > 0 || identity >= 2
	}
	lower := strings.ToLower(trimmed)
	hasSessionUI := strings.Contains(lower, "logout") || strings.Contains(lower, "log out") ||
		strings.Contains(lower, "sign out") || strings.Contains(lower, "çıkış yap")
	hasPrivateContext := strings.Contains(lower, "my account") || strings.Contains(lower, "account settings") ||
		strings.Contains(lower, "billing") || strings.Contains(lower, "invoice") ||
		strings.Contains(lower, "order history") || strings.Contains(lower, "admin dashboard")
	return hasSessionUI && hasPrivateContext && privateAuthEmailRE.MatchString(trimmed)
}

func sameBrokenAuthResource(left, right string) bool {
	if resourceFingerprint(left) != resourceFingerprint(right) {
		return false
	}
	leftIdentity := stablePrivateJSONIdentity(left)
	rightIdentity := stablePrivateJSONIdentity(right)
	if len(leftIdentity) == 0 || len(rightIdentity) == 0 {
		leftEmails := privateAuthEmailRE.FindAllString(strings.ToLower(left), -1)
		rightLower := strings.ToLower(right)
		if len(leftEmails) > 0 {
			for _, email := range leftEmails {
				if strings.Contains(rightLower, email) {
					return true
				}
			}
			return false
		}
		// Secret-only JSON responses have no stable identity marker. Require
		// byte-for-byte semantic equality rather than letting UUID/token
		// normalization collapse two different users into the same resource.
		return canonicalJSONBody(left) == canonicalJSONBody(right)
	}
	for key, leftValues := range leftIdentity {
		rightValues := rightIdentity[key]
		for value := range leftValues {
			if _, exists := rightValues[value]; exists {
				return true
			}
		}
	}
	return false
}

func stablePrivateJSONIdentity(body string) map[string]map[string]struct{} {
	var document interface{}
	if json.Unmarshal([]byte(body), &document) != nil {
		return nil
	}
	out := map[string]map[string]struct{}{}
	var visit func(interface{})
	visit = func(current interface{}) {
		switch typed := current.(type) {
		case map[string]interface{}:
			for key, child := range typed {
				name := strings.ToLower(strings.TrimSpace(key))
				switch name {
				case "email", "phone", "account_id", "user_id", "username", "customer_id":
					if value := scalarIdentityValue(child); value != "" {
						if out[name] == nil {
							out[name] = map[string]struct{}{}
						}
						out[name][value] = struct{}{}
					}
				}
				visit(child)
			}
		case []interface{}:
			for _, child := range typed {
				visit(child)
			}
		}
	}
	visit(document)
	return out
}

func scalarIdentityValue(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return strings.ToLower(strings.TrimSpace(typed))
	case float64, bool, json.Number:
		raw, _ := json.Marshal(typed)
		return string(raw)
	default:
		return ""
	}
}

func canonicalJSONBody(body string) string {
	var document interface{}
	if json.Unmarshal([]byte(body), &document) != nil {
		return strings.TrimSpace(body)
	}
	raw, _ := json.Marshal(document)
	return string(raw)
}

func privateJSONEvidence(value interface{}) (strong, identity int) {
	seenStrong := map[string]struct{}{}
	seenIdentity := map[string]struct{}{}
	var visit func(interface{})
	visit = func(current interface{}) {
		switch typed := current.(type) {
		case map[string]interface{}:
			for key, child := range typed {
				name := strings.ToLower(strings.TrimSpace(key))
				if meaningfulJSONValue(child) {
					switch name {
					case "password", "secret", "api_key", "apikey", "access_token", "refresh_token", "session_id", "ssn", "credit_card":
						seenStrong[name] = struct{}{}
					case "email", "phone", "address", "account_id", "user_id", "username", "role", "permissions", "balance", "billing", "orders", "invoices", "organization_id", "tenant_id", "workspace_id", "company_id", "team_id", "project_id":
						seenIdentity[name] = struct{}{}
					}
				}
				visit(child)
			}
		case []interface{}:
			for _, child := range typed {
				visit(child)
			}
		}
	}
	visit(value)
	return len(seenStrong), len(seenIdentity)
}

func meaningfulJSONValue(value interface{}) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case string:
		trimmed := strings.TrimSpace(typed)
		return trimmed != "" && trimmed != "null" && trimmed != "***" && trimmed != "[redacted]"
	case []interface{}:
		return len(typed) > 0
	case map[string]interface{}:
		return len(typed) > 0
	default:
		return true
	}
}

func (r *Runner) runCSRF(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("csrf", target); !ok {
		r.emitSkip("csrf", target, reason)
		return nil
	}
	return r.runStatefulSecurityProof(ctx, "csrf", target, r.cfg.CSRFProofPolicies, statefulSecurityFinding{
		Signal: "cross_site_state_mutation", Variant: "recorded_cross_site_action",
		Title:       "Cross-site request changed protected server state",
		Description: "the cross-site action changed independently observed state, the invalid-token negative control did not, and cleanup restored the original snapshot.",
		Severity:    "High",
	})
}

func hasAmbientAuthentication(cfg config.ScanConfig) bool {
	if len(cfg.SessionCookies) > 0 {
		return true
	}
	for name := range cfg.CustomHeaders {
		if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Cookie") ||
			strings.EqualFold(name, "X-API-Key") || strings.EqualFold(name, "X-Auth-Token") || strings.EqualFold(name, "X-Token") {
			return true
		}
	}
	for _, profile := range cfg.AuthProfiles {
		if len(profile.Cookies) > 0 {
			return true
		}
		for name := range profile.Headers {
			if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "X-API-Key") ||
				strings.EqualFold(name, "X-Auth-Token") || strings.EqualFold(name, "X-Token") {
				return true
			}
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
		r.recordFinding(ctx, &out, f, "wordpress_fuzz", pr.signal)
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

func (r *Runner) runImproperAuthentication(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("improper_auth", target); !ok {
		r.emitSkip("improper_auth", target, reason)
		return nil
	}
	var out []ModuleFinding
	client, ok := r.client.(sessionlessHTTPDoer)
	if !ok {
		r.emitSkip("improper_auth", target, "HTTP client cannot create an unauthenticated probe")
		return nil
	}

	// 1. Check if unauthenticated access to a protected/sensitive endpoint returns 200 OK with sensitive data schema
	baseline, err := r.cachedEmptyProbe(ctx, target)
	if err == nil && baseline.Response.StatusCode == 200 {
		lowerBody := strings.ToLower(baseline.Response.Body)
		if strings.Contains(target.EndpointURL, "/admin") || strings.Contains(target.EndpointURL, "/api/admin") ||
			strings.Contains(target.EndpointURL, "/api/v1/config") || strings.Contains(target.EndpointURL, "/api/users") {
			if strings.Contains(lowerBody, `"users"`) || strings.Contains(lowerBody, `"admin":true`) ||
				strings.Contains(lowerBody, `"api_key"`) || strings.Contains(lowerBody, `"db_password"`) {
				p := defaultPayload("improper_auth", "missing_authentication", target.EndpointURL, "unauthenticated_sensitive_api")
				f := r.verifyAndBuildWithCandidate(ctx, "improper_auth", target, p, baseline, baseline,
					"unauthenticated_sensitive_api", false, false, "", "", func(candidate *verification.Candidate) {
						candidate.RequestedProofType = verification.ProofAnonymousAccess
						candidate.ExpectedEquivalent = true
						candidate.Observations = append(candidate.Observations,
							r.identityObservation("improper_auth", target, verification.RoleAnonymousProbe, 1, "anonymous", baseline),
						)
					})
				if f != nil {
					f.Title = "Improper Authentication: Sensitive Endpoint Accessible Without Auth"
					f.Severity = "high"
					f.Description = "The endpoint " + target.EndpointURL + " returned sensitive application data (HTTP 200 OK) without requiring any authentication."
					r.recordFinding(ctx, &out, f, "improper_auth", "unauthenticated_sensitive_api")
				}
			}
		}
	}

	// 2. Test common default auth header bypasses (e.g. Basic admin:admin, Bearer null, X-Admin-Access)
	bypasses := []struct {
		headerKey   string
		headerVal   string
		variantName string
	}{
		{"Authorization", "Basic YWRtaW46YWRtaW4=", "basic_default_credentials"}, // admin:admin
		{"Authorization", "Bearer null", "bearer_null_bypass"},
		{"X-Admin-Access", "true", "custom_header_admin_bypass"},
		{"X-Bypass-Auth", "1", "custom_header_bypass_auth"},
	}

	for _, b := range bypasses {
		if ctx.Err() != nil {
			break
		}
		headers := map[string]string{b.headerKey: b.headerVal}
		rr, err := client.DoWithoutSession(ctx, target.Method, target.EndpointURL, []byte(target.BodyTemplate), headers)
		if err != nil || rr.Response.StatusCode != 200 {
			continue
		}
		respBody := strings.ToLower(rr.Response.Body)
		if authDeniedBody(respBody) {
			continue
		}
		if strings.Contains(respBody, "admin") || strings.Contains(respBody, "success") || strings.Contains(respBody, "user") {
			p := defaultPayload("improper_auth", b.variantName, b.headerVal, b.variantName)
			f := r.verifyAndBuildWithCandidate(ctx, "improper_auth", target, p, baseline, rr,
				b.variantName, false, false, "", "", func(candidate *verification.Candidate) {
					candidate.RequestedProofType = verification.ProofAnonymousAccess
					candidate.Observations = append(candidate.Observations,
						r.identityObservation("improper_auth", target, verification.RoleAnonymousProbe, 1, b.variantName, rr),
					)
				})
			if f != nil {
				f.Title = "Improper Authentication Bypass via " + b.headerKey
				f.Severity = "critical"
				f.Description = "The endpoint accepted an unauthenticated/default authorization header (" + b.headerKey + ": " + b.headerVal + ") and granted access to protected resources."
				r.recordFinding(ctx, &out, f, "improper_auth", b.variantName)
				break
			}
		}
	}

	return out
}
