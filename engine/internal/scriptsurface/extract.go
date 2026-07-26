package scriptsurface

import (
	"net/url"
	"regexp"
	"strings"
)

// Resource is an external script, stylesheet, or iframe reference from HTML.
type Resource struct {
	URL    string `json:"url"`
	Kind   string `json:"kind"`
	Domain string `json:"domain"`
}

var (
	reScriptSrc  = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"'>\s]+)["']`)
	reLinkHref   = regexp.MustCompile(`(?i)<link[^>]+rel=["']stylesheet["'][^>]+href=["']([^"'>\s]+)["']`)
	reLinkHref2  = regexp.MustCompile(`(?i)<link[^>]+href=["']([^"'>\s]+)["'][^>]+rel=["']stylesheet["']`)
	reIframeSrc  = regexp.MustCompile(`(?i)<iframe[^>]+src=["']([^"'>\s]+)["']`)
	reSocialLink = regexp.MustCompile(`(?i)href=["'](https?://(?:www\.)?(?:twitter|x|medium|github|linkedin)\.com/[^"']+)["']`)
)

// ExtractFromHTML parses HTML for third-party loadable resources and social links.
func ExtractFromHTML(html, baseURL string) []Resource {
	var out []Resource
	seen := map[string]struct{}{}
	add := func(raw, kind string) {
		resolved := resolveURL(baseURL, raw)
		if resolved == "" || strings.HasPrefix(strings.ToLower(resolved), "data:") {
			return
		}
		u, err := url.Parse(resolved)
		if err != nil || u.Host == "" {
			return
		}
		key := kind + "|" + resolved
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, Resource{URL: resolved, Kind: kind, Domain: strings.ToLower(u.Hostname())})
	}
	for _, m := range reScriptSrc.FindAllStringSubmatch(html, -1) {
		add(m[1], "script")
	}
	for _, re := range []*regexp.Regexp{reLinkHref, reLinkHref2} {
		for _, m := range re.FindAllStringSubmatch(html, -1) {
			add(m[1], "stylesheet")
		}
	}
	for _, m := range reIframeSrc.FindAllStringSubmatch(html, -1) {
		add(m[1], "iframe")
	}
	for _, m := range reSocialLink.FindAllStringSubmatch(html, -1) {
		add(m[1], "social_link")
	}
	return out
}

// IsThirdParty reports whether resourceHost belongs to a different site than pageHost.
func IsThirdParty(resourceHost, pageHost string) bool {
	resourceHost = strings.ToLower(strings.TrimSpace(resourceHost))
	pageHost = strings.ToLower(strings.TrimSpace(pageHost))
	if resourceHost == "" || pageHost == "" || resourceHost == pageHost {
		return false
	}
	if strings.HasSuffix(resourceHost, "."+pageHost) || strings.HasSuffix(pageHost, "."+resourceHost) {
		return false
	}
	return true
}

func resolveURL(base, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	b, err := url.Parse(base)
	if err != nil {
		return ref
	}
	u, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return b.ResolveReference(u).String()
}
