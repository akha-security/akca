package urlutil

import (
	"net"
	"net/url"
	"regexp"
	"strings"
)

const MaxURLLength = 2048

var (
	embeddedSchemeRe = regexp.MustCompile(`(?i)(?:^|/)(?:https?://|%68%74%74%70|%48%54%54%50)`)
	templateTokenRe  = regexp.MustCompile(`[{][{]|[:]\w+[/)]|%\s*7[Bb]|%\s*7[Dd]|\$\{`)
	badHostRe        = regexp.MustCompile(`[\s"'<>\\]|%22|%3[Aa]%2[Ff]%2[Ff]`)
)

// IsPlausibleEndpointURL rejects javascript/data links, embedded URLs, templates, and malformed hosts.
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
	if ip := net.ParseIP(host); ip == nil {
		if !strings.Contains(host, ".") && host != "localhost" {
			return false
		}
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
