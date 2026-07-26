package verification

import (
	"fmt"
	"strings"
)

type ErrorFingerprint struct {
	Source         string
	Classification string
	Action         string
	Patterns       []string
}

var ErrorFingerprintLibrary = []ErrorFingerprint{
	{Source: "Cloudflare", Classification: "waf_block", Action: "suppress", Patterns: []string{"Attention Required!", "Ray ID", "cf-ray"}},
	{Source: "Cloudflare_520", Classification: "waf_block", Action: "suppress", Patterns: []string{"Web server is returning an unknown error", "cloudflare"}},
	{Source: "Cloudflare_CDN", Classification: "waf_block", Action: "suppress", Patterns: []string{"cloudflare-nginx", "Error 52"}},
	{Source: "AWS WAF", Classification: "waf_block", Action: "suppress", Patterns: []string{"Request blocked", "AWS WAF"}},
	{Source: "Akamai", Classification: "waf_block", Action: "suppress", Patterns: []string{"Access Denied", "Reference #"}},
	{Source: "ModSecurity", Classification: "waf_block", Action: "suppress", Patterns: []string{"ModSecurity", "Not Acceptable"}},
	{Source: "Imperva", Classification: "waf_block", Action: "suppress", Patterns: []string{"Incapsula", "imperva"}},
	{Source: "Laravel", Classification: "framework_error", Action: "downgrade", Patterns: []string{"Whoops", "laravel"}},
	{Source: "Django", Classification: "framework_error", Action: "downgrade", Patterns: []string{"Django Version", "Traceback"}},
	{Source: "Rails", Classification: "framework_error", Action: "downgrade", Patterns: []string{"Rails.root", "ActionController"}},
	{Source: "ASP.NET", Classification: "framework_error", Action: "downgrade", Patterns: []string{"Server Error in", "ASP.NET"}},
	{Source: "Spring", Classification: "framework_error", Action: "downgrade", Patterns: []string{"Whitelabel Error Page", "springframework"}},
	{Source: "Generic404", Classification: "generic_error", Action: "downgrade", Patterns: []string{"404 Not Found", "Page Not Found"}},
	{Source: "Generic500", Classification: "generic_error", Action: "downgrade", Patterns: []string{"500 Internal Server Error", "Internal Server Error"}},
}

func MatchErrorFingerprint(body string, status int, headers map[string]string) (ErrorFingerprint, bool) {
	// Cloudflare-specific status codes (520-527) are always CDN errors.
	if status >= 520 && status <= 527 {
		return ErrorFingerprint{
			Source:         fmt.Sprintf("Cloudflare_%d", status),
			Classification: "waf_block",
			Action:         "suppress",
		}, true
	}
	lower := strings.ToLower(body)
	for _, fp := range ErrorFingerprintLibrary {
		if fingerprintMatches(lower, fp.Patterns) {
			return fp, true
		}
	}
	if status == 401 || status == 403 {
		if strings.Contains(lower, "login") || strings.Contains(lower, "sign in") {
			return ErrorFingerprint{Source: "LoginRedirect", Classification: "login_redirect", Action: "downgrade"}, true
		}
	}
	for k, v := range headers {
		if strings.EqualFold(k, "Location") && (strings.Contains(strings.ToLower(v), "login") || strings.Contains(strings.ToLower(v), "signin")) {
			return ErrorFingerprint{Source: "LoginRedirect", Classification: "login_redirect", Action: "downgrade"}, true
		}
	}
	return ErrorFingerprint{}, false
}

// fingerprintMatches prevents generic fragments such as "Not Acceptable",
// "Access Denied", or "Internal Server Error" from identifying a specific
// WAF/framework on their own. Multiple-pattern fingerprints require all
// fragments unless the response contains a vendor-unique marker.
func fingerprintMatches(lowerBody string, patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}
	matched := 0
	for _, pattern := range patterns {
		p := strings.ToLower(pattern)
		if !strings.Contains(lowerBody, p) {
			continue
		}
		matched++
		switch p {
		case "modsecurity", "aws waf", "cloudflare-nginx", "incapsula", "imperva":
			return true
		}
	}
	return matched >= 2 || matched == len(patterns)
}

func IsWAFBlockPage(body string) bool {
	fp, ok := MatchErrorFingerprint(body, 403, nil)
	return ok && fp.Classification == "waf_block"
}

func IsSoft404(base, probe ResponseSnapshot) bool {
	if probe.StatusCode == 404 {
		return false
	}
	return probe.StatusCode == 200 && abs(len(base.Body)-len(probe.Body)) <= 16 &&
		hashBody(base.Body) == hashBody(probe.Body)
}
