package modules

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

var sensitiveCookiePatterns = []string{
	"sess", "session", "phpsessid", "jsessionid", "aspnetsessionid",
	"connect.sid", "laravel_session", "token", "auth", "jwt",
	"sid", "remember", "user_session", "_session_id", "authtoken",
}

type parsedCookie struct {
	name   string
	flags  map[string]bool
	values map[string]string
}

func (r *Runner) runCookieSecurity(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("cookie_security", target); !ok {
		r.emitSkip("cookie_security", target, reason)
		return nil
	}
	if !r.endpointModuleOnce("cookie_security", target) {
		return nil
	}
	rr, err := r.cachedEmptyProbe(ctx, target)
	if err != nil {
		return nil
	}
	u, err := url.Parse(target.EndpointURL)
	if err != nil {
		return nil
	}
	isHTTPS := strings.EqualFold(u.Scheme, "https")

	rawCookies := extractSetCookieHeaders(rr.Response.Headers)
	if len(rawCookies) == 0 {
		return nil
	}

	baseline := httpclient.RequestResponse{
		Response: httpclient.ResponseRecord{StatusCode: 200, Body: "", Headers: map[string]string{}},
	}
	var out []ModuleFinding

	for _, raw := range rawCookies {
		c := parseCookieAttributes(raw)
		if c.name == "" {
			continue
		}
		isSensitive := isSensitiveCookieName(c.name)
		hasSecure := c.flags["secure"]
		hasHttpOnly := c.flags["httponly"]
		sameSite := c.values["samesite"]
		domain := c.values["domain"]
		path := c.values["path"]

		// 1. Missing Secure flag on HTTPS
		if isHTTPS && !hasSecure && isSensitive && r.cookieFindingOnce(u.Host, c.name, "cookie_missing_secure") {
			signal := "cookie_missing_secure"
			p := defaultPayload("cookie_security", signal, c.name, signal)
			f := r.verifyAndBuild(ctx, "cookie_security", target, p, baseline, rr, signal, false, false, "", "")
			if f != nil {
				f.Title = fmt.Sprintf("Sensitive cookie %q missing Secure flag", c.name)
				f.Severity = "medium"
				f.Description = fmt.Sprintf("The sensitive cookie %q was transmitted over HTTPS without the Secure attribute, allowing it to be transmitted over unencrypted HTTP.", c.name)
			}
			r.recordFinding(ctx, &out, f, "cookie_security", signal)
		}

		// 2. Missing HttpOnly flag on sensitive cookies
		if !hasHttpOnly && isSensitive && r.cookieFindingOnce(u.Host, c.name, "cookie_missing_httponly") {
			signal := "cookie_missing_httponly"
			p := defaultPayload("cookie_security", signal, c.name, signal)
			f := r.verifyAndBuild(ctx, "cookie_security", target, p, baseline, rr, signal, false, false, "", "")
			if f != nil {
				f.Title = fmt.Sprintf("Session cookie %q missing HttpOnly flag", c.name)
				f.Severity = "medium"
				f.Description = fmt.Sprintf("The cookie %q lacks the HttpOnly attribute, making it accessible to JavaScript and vulnerable to XSS-based theft.", c.name)
			}
			r.recordFinding(ctx, &out, f, "cookie_security", signal)
		}

		// 3. Missing or weak SameSite attribute
		if isSensitive && (sameSite == "" || (strings.EqualFold(sameSite, "none") && !hasSecure)) && r.cookieFindingOnce(u.Host, c.name, "cookie_weak_samesite") {
			signal := "cookie_weak_samesite"
			p := defaultPayload("cookie_security", signal, c.name, signal)
			f := r.verifyAndBuild(ctx, "cookie_security", target, p, baseline, rr, signal, false, false, "", "")
			if f != nil {
				f.Title = fmt.Sprintf("Session cookie %q missing or weak SameSite attribute", c.name)
				f.Severity = "low"
				f.Description = fmt.Sprintf("The cookie %q does not enforce strict or lax SameSite policies, increasing CSRF risk across cross-site contexts.", c.name)
			}
			r.recordFinding(ctx, &out, f, "cookie_security", signal)
		}

		// 4. __Host- prefix violation
		if strings.HasPrefix(c.name, "__Host-") && (!hasSecure || domain != "" || path != "/") && r.cookieFindingOnce(u.Host, c.name, "cookie_host_prefix_violation") {
			signal := "cookie_host_prefix_violation"
			p := defaultPayload("cookie_security", signal, c.name, signal)
			f := r.verifyAndBuild(ctx, "cookie_security", target, p, baseline, rr, signal, false, false, "", "")
			if f != nil {
				f.Title = fmt.Sprintf("__Host- cookie prefix rule violation for %q", c.name)
				f.Severity = "medium"
				f.Description = fmt.Sprintf("The cookie %q uses the __Host- prefix but violates RFC 6265bis requirements (must be Secure, Path=/, and have no Domain attribute).", c.name)
			}
			r.recordFinding(ctx, &out, f, "cookie_security", signal)
		}

		// 5. __Secure- prefix violation
		if strings.HasPrefix(c.name, "__Secure-") && !hasSecure && r.cookieFindingOnce(u.Host, c.name, "cookie_secure_prefix_violation") {
			signal := "cookie_secure_prefix_violation"
			p := defaultPayload("cookie_security", signal, c.name, signal)
			f := r.verifyAndBuild(ctx, "cookie_security", target, p, baseline, rr, signal, false, false, "", "")
			if f != nil {
				f.Title = fmt.Sprintf("__Secure- cookie prefix rule violation for %q", c.name)
				f.Severity = "low"
				f.Description = fmt.Sprintf("The cookie %q uses the __Secure- prefix but is missing the Secure attribute.", c.name)
			}
			r.recordFinding(ctx, &out, f, "cookie_security", signal)
		}
	}

	return out
}

func (r *Runner) cookieFindingOnce(host, cookieName, signal string) bool {
	key := "cookie_security::" + strings.ToLower(host) + "::" + strings.ToLower(cookieName) + "::" + strings.ToLower(signal)
	r.moduleSeenMu.Lock()
	defer r.moduleSeenMu.Unlock()
	if _, exists := r.moduleSeen[key]; exists {
		return false
	}
	r.moduleSeen[key] = struct{}{}
	return true
}

func extractSetCookieHeaders(headers map[string]string) []string {
	var out []string
	for k, v := range headers {
		if strings.EqualFold(k, "set-cookie") {
			parts := strings.Split(v, "\n")
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p != "" {
					out = append(out, p)
				}
			}
		}
	}
	return out
}

func parseCookieAttributes(raw string) parsedCookie {
	res := parsedCookie{
		flags:  make(map[string]bool),
		values: make(map[string]string),
	}
	parts := strings.Split(raw, ";")
	if len(parts) == 0 {
		return res
	}

	first := strings.TrimSpace(parts[0])
	name, _, _ := strings.Cut(first, "=")
	res.name = strings.TrimSpace(name)

	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		k, v, hasVal := strings.Cut(p, "=")
		kLower := strings.ToLower(strings.TrimSpace(k))
		res.flags[kLower] = true
		if hasVal {
			res.values[kLower] = strings.TrimSpace(v)
		}
	}
	return res
}

func isSensitiveCookieName(name string) bool {
	lower := strings.ToLower(name)
	for _, pat := range sensitiveCookiePatterns {
		if strings.Contains(lower, pat) {
			return true
		}
	}
	return false
}
