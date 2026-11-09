package urlutil

import (
	"net/url"
	"regexp"
	"strings"
)

const MaxURLLength = 2048

// HasPathTemplate identifies JS/router placeholders that need real values
// before a request can validate the endpoint. Keep them in discovery inventory.
func HasPathTemplate(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if strings.ContainsAny(u.Path, "{}[]") {
		return true
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if len(segment) > 1 && segment[0] == ':' {
			return true
		}
	}
	return false
}

var (
	embeddedSchemeRe = regexp.MustCompile(`(?i)(?:^|/)(?:https?://|%68%74%74%70|%48%54%54%50)`)
	templateTokenRe  = regexp.MustCompile(`[{][{]|[:]\w+[/)]|\$\{`)
	badHostRe        = regexp.MustCompile(`[\s"'<>\\]|%22|%3[Aa]%2[Ff]%2[Ff]`)
)

// IsPlausibleEndpointURL rejects javascript/data links, embedded URLs, templates, semantic garbage, and malformed hosts.
func IsPlausibleEndpointURL(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > MaxURLLength {
		return false
	}
	lower := strings.ToLower(raw)
	for _, prefix := range []string{"javascript:", "data:", "blob:", "mailto:", "tel:", "vbscript:"} {
		if strings.HasPrefix(lower, prefix) {
			return false
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return false
	}
	host := u.Hostname()
	if host == "" || badHostRe.MatchString(host) {
		return false
	}
	pathQuery := u.Path + "?" + u.RawQuery
	if embeddedSchemeRe.MatchString(pathQuery) {
		return false
	}
	if templateTokenRe.MatchString(pathQuery) {
		return false
	}
	if strings.Count(u.Path, "/") > 64 {
		return false
	}

	lowerPath := strings.ToLower(u.Path)
	// JS string extraction can accidentally capture an entire minified
	// expression. Inspect the decoded path, including URL-encoded operators;
	// punctuation in query values and valid matrix/OData paths stays valid.
	for _, fragment := range []string{"&&", "||", "=>", "function(", "function (", ".exports)", ".exports=", ".exports,", "){", ";return "} {
		if strings.Contains(lowerPath, fragment) {
			return false
		}
	}
	// Reject semantic noise and JS artifacts
	for _, noise := range []string{
		"/undefined", "/null", "/nan", "/[object object]",
		"/dd/mm/yyyy", "/mm/dd/yyyy", "/yyyy/mm/dd",
		"/node_modules/", "/bower_components/",
	} {
		if strings.Contains(lowerPath, noise) {
			return false
		}
	}

	for _, vals := range u.Query() {
		for _, v := range vals {
			vl := strings.ToLower(strings.TrimSpace(v))
			if strings.Contains(v, "://") || strings.Contains(vl, "%3a%2f%2f") || strings.Contains(vl, "http%3") {
				return false
			}
		}
	}
	return true
}
