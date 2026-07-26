package crawler

import (
	"regexp"
	"strings"

	"github.com/akha-security/akca/engine/internal/urlutil"
)

var (
	reHref        = regexp.MustCompile(`(?i)<a[^>]+href=["']([^"']+)["']`)
	reMetaRefresh = regexp.MustCompile(`(?i)<meta[^>]+http-equiv=["']refresh["'][^>]+content=["'][^"']*url=([^"';]+)`)
	reCanonical   = regexp.MustCompile(`(?i)<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']+)["']`)
	reScriptSrc  = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
	reInlineURL  = regexp.MustCompile(`(?i)(?:fetch|axios|XMLHttpRequest|\.open)\s*\(\s*["']([^"']+)["']`)
	reHTMLComment = regexp.MustCompile(`<!--([\s\S]*?)-->`)
	reCSSUrl     = regexp.MustCompile(`(?i)url\(["']?([^"')]+)["']?\)`)
	reLinkCSS    = regexp.MustCompile(`(?i)<link[^>]+rel=["']stylesheet["'][^>]+href=["']([^"']+)["']`)
	reDataAttr   = regexp.MustCompile(`(?i)data-(?:href|url|src|endpoint|api)=["']([^"']+)["']`)
	reSrcset     = regexp.MustCompile(`(?i)\ssrcset=["']([^"']+)["']`)
	reImgSrc     = regexp.MustCompile(`(?i)<img[^>]+src=["']([^"']+)["']`)
	reIframeSrc  = regexp.MustCompile(`(?i)<iframe[^>]+src=["']([^"']+)["']`)
	reVideoSrc   = regexp.MustCompile(`(?i)<(?:video|audio|source|embed|object)[^>]+(?:src|data)=["']([^"']+)["']`)
	reAreaHref   = regexp.MustCompile(`(?i)<area[^>]+href=["']([^"']+)["']`)
	reBaseHref   = regexp.MustCompile(`(?i)<base[^>]+href=["']([^"']+)["']`)
	reRobotsLine = regexp.MustCompile(`(?i)^(?:allow|disallow|sitemap):\s*(\S+)`)
	reSitemapLoc = regexp.MustCompile(`(?i)<loc>([^<]+)</loc>`)
)

func ExtractFromHTML(baseURL, html string) []DiscoveredEndpoint {
	var out []DiscoveredEndpoint
	add := func(rawURL string, source DiscoverySource, confidence float64, why string) {
		resolved, err := ResolveReference(baseURL, rawURL)
		if err != nil || resolved == "" || !urlutil.IsPlausibleEndpointURL(resolved) {
			return
		}
		out = append(out, DiscoveredEndpoint{
			URL:           resolved,
			Method:        "GET",
			Source:        source,
			Confidence:    confidence,
			WhyDiscovered: why,
		})
	}

	for _, m := range reHref.FindAllStringSubmatch(html, -1) {
		add(m[1], SourceLink, 0.9, "anchor href")
	}
	out = append(out, extractForms(baseURL, html)...)
	for _, m := range reMetaRefresh.FindAllStringSubmatch(html, -1) {
		add(m[1], SourceMetaRefresh, 0.85, "meta refresh redirect")
	}
	for _, m := range reCanonical.FindAllStringSubmatch(html, -1) {
		add(m[1], SourceCanonical, 0.8, "canonical link")
	}
	for _, m := range reScriptSrc.FindAllStringSubmatch(html, -1) {
		add(m[1], SourceScript, 0.9, "script src")
	}
	for _, m := range reInlineURL.FindAllStringSubmatch(html, -1) {
		add(m[1], SourceInlineJS, 0.75, "inline js url reference")
	}
	for _, m := range reHTMLComment.FindAllStringSubmatch(html, -1) {
		for _, u := range extractURLsFromText(m[1]) {
			add(u, SourceHTMLComment, 0.5, "url in html comment")
		}
	}
	for _, m := range reLinkCSS.FindAllStringSubmatch(html, -1) {
		add(m[1], SourceCSS, 0.7, "stylesheet href")
	}
	for _, m := range reCSSUrl.FindAllStringSubmatch(html, -1) {
		add(m[1], SourceCSS, 0.6, "css url() reference")
	}
	for _, m := range reDataAttr.FindAllStringSubmatch(html, -1) {
		add(m[1], SourceDataAttr, 0.7, "data-* attribute url")
	}
	for _, m := range reSrcset.FindAllStringSubmatch(html, -1) {
		for _, part := range strings.Split(m[1], ",") {
			fields := strings.Fields(strings.TrimSpace(part))
			if len(fields) > 0 {
				add(fields[0], SourceSrcset, 0.5, "srcset candidate")
			}
		}
	}
	for _, m := range reImgSrc.FindAllStringSubmatch(html, -1) {
		add(m[1], SourceImage, 0.55, "img src")
	}
	for _, m := range reIframeSrc.FindAllStringSubmatch(html, -1) {
		add(m[1], SourceIframe, 0.65, "iframe src")
	}
	for _, m := range reVideoSrc.FindAllStringSubmatch(html, -1) {
		add(m[1], SourceMedia, 0.5, "media src")
	}
	for _, m := range reAreaHref.FindAllStringSubmatch(html, -1) {
		add(m[1], SourceLink, 0.55, "area href")
	}
	for _, m := range reBaseHref.FindAllStringSubmatch(html, -1) {
		add(m[1], SourceCanonical, 0.7, "base href")
	}
	return out
}

func ExtractFromRobots(baseURL, body string) []DiscoveredEndpoint {
	var out []DiscoveredEndpoint
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		m := reRobotsLine.FindStringSubmatch(line)
		if len(m) < 2 {
			continue
		}
		resolved, err := ResolveReference(baseURL, m[1])
		if err != nil || resolved == "" {
			continue
		}
		source := SourceRobots
		why := "robots.txt entry"
		if strings.HasPrefix(strings.ToLower(line), "sitemap:") {
			source = SourceSitemap
			why = "robots sitemap directive"
		}
		out = append(out, DiscoveredEndpoint{
			URL: resolved, Method: "GET", Source: source, Confidence: 0.85, WhyDiscovered: why,
		})
	}
	return out
}

func ExtractFromSitemap(body string) []DiscoveredEndpoint {
	var out []DiscoveredEndpoint
	for _, m := range reSitemapLoc.FindAllStringSubmatch(body, -1) {
		out = append(out, DiscoveredEndpoint{
			URL: m[1], Method: "GET", Source: SourceSitemap, Confidence: 0.9, WhyDiscovered: "sitemap loc",
		})
	}
	return out
}

func extractURLsFromText(text string) []string {
	re := regexp.MustCompile(`https?://[^\s"'<>]+|/[a-zA-Z0-9_./?&=%-]+`)
	return re.FindAllString(text, -1)
}
