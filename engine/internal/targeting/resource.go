// Package targeting classifies discovered resources before active mutation.
// Inventory and passive content analysis deliberately retain static resources.
package targeting

import (
	"github.com/akha-security/akca/engine/internal/urlutil"
	"net/url"
	"path"
	"strings"
)

type Resource struct {
	URL, Method, ContentType, Body string
	Status                         int
	DynamicInput                   bool // observed reflection, a captured body, or an explicit API contract
	ForceActive                    bool
}

func IsChallenge(status int, body string) bool {
	lower := strings.ToLower(body)
	for _, marker := range []string{"checking your browser", "cf-browser-verification", "captcha challenge", "your support id is", "requested url was rejected"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return (status == 403 || status == 429 || status == 503) &&
		(strings.Contains(lower, "request blocked") || strings.Contains(lower, "web application firewall"))
}

// InactiveReason is independent of the module's payload budget or full-coverage
// setting. A filename alone can be overridden by observed dynamic input.
func InactiveReason(r Resource) string {
	if r.Status == 404 || r.Status == 410 {
		return "resource is not found or gone"
	}
	if r.Status == 429 || r.Status >= 500 || IsChallenge(r.Status, r.Body) {
		return "resource is rate-limited, challenged or unavailable"
	}
	u, err := url.Parse(r.URL)
	if err != nil {
		return "invalid endpoint URL"
	}
	if r.URL != "" {
		endpoint := *u
		endpoint.RawQuery, endpoint.Fragment = "", ""
		if !urlutil.IsPlausibleEndpointURL(endpoint.String()) {
			return "invalid or code-derived endpoint path"
		}
	}
	if r.ForceActive {
		return ""
	}
	p := strings.ToLower(strings.TrimRight(u.Path, "/"))
	base := path.Base(p)
	if base == "robots.txt" || (strings.HasPrefix(base, "sitemap") && strings.HasSuffix(base, ".xml")) ||
		base == "openapi.json" || base == "swagger.json" || base == "asyncapi.json" || base == "package.json" || base == "package-lock.json" ||
		p == "/.well-known" || strings.HasPrefix(p, "/.well-known/") {
		return "discovery document; inspect its contents instead of mutating it"
	}
	ct := strings.ToLower(r.ContentType)
	structured := strings.Contains(ct, "json") || strings.HasPrefix(ct, "application/xml") || strings.HasPrefix(ct, "text/xml")
	dynamic := r.DynamicInput || (structured && !strings.HasSuffix(p, ".map") && base != "manifest.json") ||
		(strings.Contains(ct, "html") && strings.Contains(strings.ToLower(r.Body), "<form"))
	if dynamic {
		return ""
	}
	for _, ext := range []string{".js", ".mjs", ".cjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif", ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".pdf", ".zip", ".gz", ".br"} {
		if strings.HasSuffix(p, ext) {
			return "static resource; passive analysis retained"
		}
	}
	for _, prefix := range []string{"/assets", "/static", "/images", "/fonts", "/css", "/js", "/_next/static"} {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return "static resource directory; passive analysis retained"
		}
	}
	if strings.Contains(ct, "javascript") || strings.HasPrefix(ct, "image/") || strings.HasPrefix(ct, "font/") || strings.Contains(ct, "text/css") {
		return "static response content type; passive analysis retained"
	}
	return ""
}

// BypassCandidate excludes asset trees and generic discovery artifacts before
// they can expand into dozens of path/header variants. A canonical 403 alone
// does not establish that an application handler exists.
func BypassCandidate(raw string) bool {
	_, err := url.Parse(raw)
	if err != nil || InactiveReason(Resource{URL: raw}) != "" {
		return false
	}
	return true // unknown application routes remain candidates
}

func ForcedURL(raw string, overrides []string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	u.Fragment = ""
	for _, value := range overrides {
		v, err := url.Parse(value)
		if err != nil {
			continue
		}
		v.Fragment = ""
		if u.String() == v.String() {
			return true
		}
	}
	return false
}
