package crawler

import (
	"html"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

var (
	dynamicRoutePatterns = []*regexp.Regexp{
		regexp.MustCompile(`/:([a-zA-Z_][a-zA-Z0-9_]*)`),
		regexp.MustCompile(`/\{([a-zA-Z_][a-zA-Z0-9_]*)\}`),
		regexp.MustCompile(`/\[([a-zA-Z_][a-zA-Z0-9_]*)\]`),
	}
	reNumericPathSegment = regexp.MustCompile(`/\d+(/|$)`)
	reUUIDPathSegment    = regexp.MustCompile(`(?i)/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(/|$)`)
	reHexPathSegment     = regexp.MustCompile(`(?i)/[0-9a-f]{16,64}(/|$)`)
)

// NormalizeRESTPath collapses dynamic numerical IDs, UUIDs, and hashes into canonical RESTful path templates.
func NormalizeRESTPath(path string) string {
	r := reUUIDPathSegment.ReplaceAllString(path, "/{uuid}$1")
	r = reNumericPathSegment.ReplaceAllString(r, "/{id}$1")
	r = reHexPathSegment.ReplaceAllString(r, "/{hash}$1")
	return r
}

// NormalizeURL canonicalizes a URL for deduplication.
func NormalizeURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	u.Fragment = ""
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimSuffix(u.Path, "/")
	if u.Path == "" {
		u.Path = "/"
	}

	q := u.Query()
	if len(q) > 0 {
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		clean := url.Values{}
		for _, k := range keys {
			vals := q[k]
			sort.Strings(vals)
			for _, v := range vals {
				clean.Add(k, v)
			}
		}
		u.RawQuery = clean.Encode()
	}
	return u.String(), nil
}

// NormalizeRouteTemplate converts dynamic route patterns to a canonical /{name} form while preserving parameter names.
func NormalizeRouteTemplate(route string) string {
	r := route
	for _, re := range dynamicRoutePatterns {
		r = re.ReplaceAllString(r, "/{$1}")
	}
	r = strings.ReplaceAll(r, "//", "/")
	return r
}

// StructuralRouteFingerprint converts dynamic route patterns to a structural /:param form for clustering.
func StructuralRouteFingerprint(route string) string {
	r := route
	for _, re := range dynamicRoutePatterns {
		r = re.ReplaceAllString(r, "/:param")
	}
	r = strings.ReplaceAll(r, "//", "/")
	return r
}

// ResolveReference resolves a possibly relative URL against a base page URL.
func ResolveReference(baseURL, ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	ref = html.UnescapeString(ref)
	ref = strings.Trim(ref, `"'`+" \t\r\n")
	if ref == "" || strings.HasPrefix(ref, "#") || strings.HasPrefix(strings.ToLower(ref), "javascript:") || strings.HasPrefix(strings.ToLower(ref), "mailto:") || strings.HasPrefix(strings.ToLower(ref), "tel:") || strings.HasPrefix(strings.ToLower(ref), "data:") {
		return "", nil
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	rel, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(rel).String(), nil
}

func dedupeKey(method, normalized string) string {
	return strings.ToUpper(method) + " " + normalized
}
