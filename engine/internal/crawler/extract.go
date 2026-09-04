package crawler

import (
	"html"
	"regexp"
	"strings"

	"github.com/akha-security/akca/engine/internal/urlutil"
	nethtml "golang.org/x/net/html"
)

var (
	reHref         = regexp.MustCompile(`(?i)<a[^>]+href=(?:"([^"]+)"|'([^']+)'|([^\s>]+))`)
	reMetaRefresh  = regexp.MustCompile(`(?i)<meta[^>]+http-equiv=["']refresh["'][^>]+content=["'][^"']*url=([^"';]+)`)
	reCanonical    = regexp.MustCompile(`(?i)<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']+)["']`)
	reScriptSrc    = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
	reInlineURL    = regexp.MustCompile(`(?i)(?:fetch|axios|XMLHttpRequest|\.open)\s*\(\s*["']([^"']+)["']`)
	reHTMLComment  = regexp.MustCompile(`<!--([\s\S]*?)-->`)
	reCSSUrl       = regexp.MustCompile(`(?i)url\(["']?([^"')]+)["']?\)`)
	reLinkCSS      = regexp.MustCompile(`(?i)<link[^>]+rel=["']stylesheet["'][^>]+href=["']([^"']+)["']`)
	reDataAttr     = regexp.MustCompile(`(?i)data-(?:href|url|src|endpoint|api)=["']([^"']+)["']`)
	reSrcset       = regexp.MustCompile(`(?i)\ssrcset=["']([^"']+)["']`)
	reImgSrc       = regexp.MustCompile(`(?i)<img[^>]+src=["']([^"']+)["']`)
	reIframeSrc    = regexp.MustCompile(`(?i)<iframe[^>]+src=["']([^"']+)["']`)
	reVideoSrc     = regexp.MustCompile(`(?i)<(?:video|audio|source|embed|object)[^>]+(?:src|data)=["']([^"']+)["']`)
	reAreaHref     = regexp.MustCompile(`(?i)<area[^>]+href=["']([^"']+)["']`)
	reBaseHref     = regexp.MustCompile(`(?i)<base[^>]+href=["']([^"']+)["']`)
	reOnClickAttr  = regexp.MustCompile(`(?i)(?:onclick|@click|v-on:click|ng-click|on-click)=["']([^"']+)["']`)
	reDataAction   = regexp.MustCompile(`(?i)data-(?:action|target|endpoint|route|api|url|href)=["']([^"']+)["']`)
	reJSONState    = regexp.MustCompile(`(?i)<script[^>]*type=["']application/json["'][^>]*>([\s\S]*?)</script>`)
	reNextState    = regexp.MustCompile(`(?i)<script[^>]*id=["']__NEXT_DATA__["'][^>]*>([\s\S]*?)</script>`)
	reWindowState  = regexp.MustCompile(`(?i)window\.(?:__INITIAL_STATE__|__NEXT_DATA__|ENV|AppConfig|config)\s*=\s*(\{[\s\S]*?\});`)
	reAPIBaseURL   = regexp.MustCompile(`(?i)(?:baseURL|apiUrl|apiEndpoint|apiHost|serverUrl|endpointUrl)\s*[:=]\s*["']([^"']+)["']`)
	reAxiosBase    = regexp.MustCompile(`(?i)axios\.create\s*\(\s*\{[^}]*baseURL\s*:\s*["']([^"']+)["']`)
	reEnvConfig    = regexp.MustCompile(`(?i)(?:REACT_APP_API_URL|VITE_API_URL|NEXT_PUBLIC_API_URL|API_BASE_URL|API_HOST)\s*[:=]\s*["']([^"']+)["']`)
	reAPISpec      = regexp.MustCompile(`(?i)["']([^"']*(?:swagger|openapi|asyncapi|api-docs)[^"']*\.(?:json|yaml|yml))["']`)
	reWorkerScript = regexp.MustCompile(`(?i)new\s+Worker\s*\(\s*["']([^"']+)["']`)
	reRobotsLine   = regexp.MustCompile(`(?i)^(?:allow|disallow|sitemap):\s*(\S+)`)
	reSitemapLoc   = regexp.MustCompile(`(?i)<loc>([^<]+)</loc>`)
)

func ExtractFromHTML(baseURL, htmlContent string) []DiscoveredEndpoint {
	var out []DiscoveredEndpoint
	seen := make(map[string]struct{})

	currentBaseURL := baseURL

	add := func(rawURL string, source DiscoverySource, confidence float64, why string) {
		rawURL = html.UnescapeString(strings.TrimSpace(rawURL))
		rawURL = strings.Trim(rawURL, `"'`+" \t\r\n")
		resolved, err := ResolveReference(currentBaseURL, rawURL)
		if err != nil || resolved == "" || !urlutil.IsPlausibleEndpointURL(resolved) {
			return
		}
		key := "GET " + resolved
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, DiscoveredEndpoint{
			URL:           resolved,
			Method:        "GET",
			Source:        source,
			Confidence:    confidence,
			WhyDiscovered: why,
		})
	}

	// 1. Full DOM Tree Parsing via golang.org/x/net/html
	if doc, err := nethtml.Parse(strings.NewReader(htmlContent)); err == nil {
		var walk func(*nethtml.Node)
		walk = func(n *nethtml.Node) {
			if n.Type == nethtml.ElementNode {
				tag := strings.ToLower(n.Data)
				if tag == "base" {
					for _, a := range n.Attr {
						if strings.EqualFold(a.Key, "href") && a.Val != "" {
							if res, err := ResolveReference(baseURL, a.Val); err == nil && res != "" {
								currentBaseURL = res
							}
						}
					}
				}

				for _, a := range n.Attr {
					key := strings.ToLower(a.Key)
					val := strings.TrimSpace(a.Val)
					if val == "" {
						continue
					}
					switch key {
					case "href":
						if tag == "a" || tag == "area" {
							add(val, SourceLink, 0.95, "html anchor/area href")
						} else if tag == "link" {
							add(val, SourceLink, 0.85, "html link href")
						}
					case "src":
						if tag == "script" {
							add(val, SourceScript, 0.9, "script src")
						} else if tag == "iframe" || tag == "frame" {
							add(val, SourceIframe, 0.8, "frame src")
						} else {
							add(val, SourceImage, 0.5, "media src")
						}
					case "formaction":
						add(val, SourceForm, 0.9, "formaction attribute")
					case "action":
						if tag == "form" {
							add(val, SourceForm, 0.95, "form action")
						}
					case "data-href", "data-url", "data-target", "data-action", "data-endpoint", "data-api", "data-src":
						add(val, SourceDataAttr, 0.8, "html "+key+" attribute")
					case "onclick", "onchange", "onmouseover", "onmousedown":
						for _, u := range extractURLsFromText(val) {
							add(u, SourceInlineJS, 0.75, "dom event handler url")
						}
					case "value":
						if tag == "option" && (strings.Contains(val, "/") || strings.Contains(val, ".php") || strings.Contains(val, ".asp") || strings.Contains(val, ".jsp") || strings.Contains(val, "?")) {
							add(val, SourceLink, 0.7, "option value url")
						}
					}
				}
			}
			for child := n.FirstChild; child != nil; child = child.NextSibling {
				walk(child)
			}
		}
		walk(doc)
	}

	// 2. Forms extraction (actions, input controls and request templates)
	for _, f := range extractForms(currentBaseURL, htmlContent) {
		key := f.Method + " " + f.URL
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			out = append(out, f)
		}
	}

	// 3. Regex Fallback & Script extraction for inline JS, comments, and config blobs
	for _, m := range reHref.FindAllStringSubmatch(htmlContent, -1) {
		val := m[1]
		if val == "" {
			val = m[2]
		}
		if val == "" {
			val = m[3]
		}
		if val != "" {
			add(val, SourceLink, 0.9, "anchor href regex")
		}
	}
	for _, m := range reMetaRefresh.FindAllStringSubmatch(htmlContent, -1) {
		add(m[1], SourceMetaRefresh, 0.85, "meta refresh redirect")
	}
	for _, m := range reCanonical.FindAllStringSubmatch(htmlContent, -1) {
		add(m[1], SourceCanonical, 0.8, "canonical link")
	}
	for _, m := range reScriptSrc.FindAllStringSubmatch(htmlContent, -1) {
		add(m[1], SourceScript, 0.9, "script src regex")
	}
	for _, m := range reInlineURL.FindAllStringSubmatch(htmlContent, -1) {
		add(m[1], SourceInlineJS, 0.75, "inline js url reference")
	}
	for _, m := range reOnClickAttr.FindAllStringSubmatch(htmlContent, -1) {
		for _, u := range extractURLsFromText(m[1]) {
			add(u, SourceInlineJS, 0.7, "dom onclick event handler")
		}
	}
	for _, m := range reDataAction.FindAllStringSubmatch(htmlContent, -1) {
		add(m[1], SourceDataAttr, 0.75, "data-action/endpoint attribute")
	}
	for _, m := range reJSONState.FindAllStringSubmatch(htmlContent, -1) {
		for _, u := range extractURLsFromText(m[1]) {
			add(u, SourceInlineJS, 0.8, "embedded json state script")
		}
	}
	for _, m := range reNextState.FindAllStringSubmatch(htmlContent, -1) {
		for _, u := range extractURLsFromText(m[1]) {
			add(u, SourceSPARoute, 0.85, "__NEXT_DATA__ json state")
		}
	}
	for _, m := range reWindowState.FindAllStringSubmatch(htmlContent, -1) {
		for _, u := range extractURLsFromText(m[1]) {
			add(u, SourceInlineJS, 0.8, "window state object")
		}
	}
	for _, m := range reAPIBaseURL.FindAllStringSubmatch(htmlContent, -1) {
		add(m[1], SourceAPIDoc, 0.85, "api base url configuration")
	}
	for _, m := range reAxiosBase.FindAllStringSubmatch(htmlContent, -1) {
		add(m[1], SourceAPIDoc, 0.85, "axios baseURL configuration")
	}
	for _, m := range reEnvConfig.FindAllStringSubmatch(htmlContent, -1) {
		add(m[1], SourceAPIDoc, 0.85, "environment api url configuration")
	}
	for _, m := range reAPISpec.FindAllStringSubmatch(htmlContent, -1) {
		add(m[1], SourceAPIDoc, 0.9, "OpenAPI/AsyncAPI specification reference")
	}
	for _, m := range reWorkerScript.FindAllStringSubmatch(htmlContent, -1) {
		add(m[1], SourceScript, 0.75, "web worker script")
	}
	for _, m := range reHTMLComment.FindAllStringSubmatch(htmlContent, -1) {
		for _, u := range extractURLsFromText(m[1]) {
			add(u, SourceHTMLComment, 0.5, "url in html comment")
		}
	}
	for _, m := range reLinkCSS.FindAllStringSubmatch(htmlContent, -1) {
		add(m[1], SourceCSS, 0.7, "stylesheet href")
	}
	for _, m := range reCSSUrl.FindAllStringSubmatch(htmlContent, -1) {
		add(m[1], SourceCSS, 0.6, "css url() reference")
	}
	for _, m := range reDataAttr.FindAllStringSubmatch(htmlContent, -1) {
		add(m[1], SourceDataAttr, 0.7, "data-* attribute url")
	}
	for _, m := range reSrcset.FindAllStringSubmatch(htmlContent, -1) {
		for _, part := range strings.Split(m[1], ",") {
			fields := strings.Fields(strings.TrimSpace(part))
			if len(fields) > 0 {
				add(fields[0], SourceSrcset, 0.5, "srcset candidate")
			}
		}
	}
	for _, m := range reImgSrc.FindAllStringSubmatch(htmlContent, -1) {
		add(m[1], SourceImage, 0.55, "img src")
	}
	for _, m := range reIframeSrc.FindAllStringSubmatch(htmlContent, -1) {
		add(m[1], SourceIframe, 0.65, "iframe src")
	}
	for _, m := range reVideoSrc.FindAllStringSubmatch(htmlContent, -1) {
		add(m[1], SourceMedia, 0.5, "media src")
	}
	for _, m := range reAreaHref.FindAllStringSubmatch(htmlContent, -1) {
		add(m[1], SourceLink, 0.55, "area href")
	}
	for _, m := range reBaseHref.FindAllStringSubmatch(htmlContent, -1) {
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
