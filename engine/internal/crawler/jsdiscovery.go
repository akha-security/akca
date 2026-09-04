package crawler

import (
	"regexp"
	"strings"
	"unicode"
)

var (
	reFetchURL      = regexp.MustCompile(`(?i)fetch\s*\(\s*["']([^"']+)["']`)
	reXHRURL        = regexp.MustCompile(`(?i)\.open\s*\(\s*["'](GET|POST|PUT|DELETE|PATCH)["']\s*,\s*["']([^"']+)["']`)
	reAxiosURL      = regexp.MustCompile(`(?i)axios\.(get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']`)
	reGraphQLPath   = regexp.MustCompile(`(?i)["'](/graphql[^"']*)["']`)
	reWebSocketURL  = regexp.MustCompile(`(?i)new\s+WebSocket\s*\(\s*["']([^"']+)["']`)
	reDynamicImport = regexp.MustCompile(`(?i)import\s*\(\s*["']([^"']+)["']\s*\)`)
	reChunkManifest = regexp.MustCompile(`(?i)["']([^"']+\.chunk\.js)["']`)
	reNextRoute     = regexp.MustCompile(`(?i)__NEXT_DATA__[^}]*"pathname"\s*:\s*"([^"]+)"`)
	reServiceWorker = regexp.MustCompile(`(?i)navigator\.serviceWorker\.register\s*\(\s*["']([^"']+)["']`)
	reManifest      = regexp.MustCompile(`(?i)<link[^>]+rel=["']manifest["'][^>]+href=["']([^"']+)["']`)
	reURLWithParams = regexp.MustCompile(`(?i)["'](/[a-zA-Z0-9_./-]+\?[a-zA-Z0-9_&=%-]+)["']`)
	reRouterConfig  = regexp.MustCompile(`(?i)(?:path|route|to)\s*:\s*["'](/[a-zA-Z0-9_/{}:\[\]-]+)["']`)
	reReactRoute    = regexp.MustCompile(`(?i)<(?:Route|NavLink|Link)\s+[^>]*(?:path|to)=["'](/[a-zA-Z0-9_/{}:\[\]-]+)["']`)
	reRouterCall    = regexp.MustCompile(`(?i)(?:navigate|navigateByUrl|history\.pushState|router\.(?:push|replace|get|post))\s*\(\s*["'](/[a-zA-Z0-9_/{}:\[\]-]+)["']`)
	reApiRoute      = regexp.MustCompile(`(?i)["'](/api/(?:v[0-9]+/|v[0-9]+)?[a-zA-Z0-9_./:-]{2,100})["']`)
)

// ExtractFromJSBundle extracts endpoints from minified or normal JavaScript.
func ExtractFromJSBundle(baseURL, js string) []DiscoveredEndpoint {
	var out []DiscoveredEndpoint
	add := func(raw, method string, kind EndpointKind, source DiscoverySource, confidence float64, why string) {
		if !looksLikeRoute(raw) && !strings.HasPrefix(strings.ToLower(raw), "http://") && !strings.HasPrefix(strings.ToLower(raw), "https://") && !strings.HasPrefix(strings.ToLower(raw), "ws://") && !strings.HasPrefix(strings.ToLower(raw), "wss://") {
			return
		}
		resolved, err := ResolveReference(baseURL, raw)
		if err != nil || resolved == "" {
			return
		}
		if strings.Contains(strings.ToLower(resolved), "graphql") {
			source = SourceGraphQL
			kind = KindAPI
		}
		if strings.HasPrefix(strings.ToLower(resolved), "ws://") || strings.HasPrefix(strings.ToLower(resolved), "wss://") {
			source = SourceWebSocket
			kind = KindAPI
		}
		out = append(out, DiscoveredEndpoint{
			URL: resolved, Method: method, NormalizedURL: resolved, Kind: kind, Source: source, Confidence: confidence, WhyDiscovered: why,
		})
	}

	for _, m := range reURLWithParams.FindAllStringSubmatch(js, -1) {
		add(m[1], "GET", KindAPI, SourceJSBundle, 0.85, "url with query parameters in js bundle")
	}

	for _, m := range reFetchURL.FindAllStringSubmatch(js, -1) {
		add(m[1], "GET", KindAPI, SourceJSBundle, 0.8, "fetch() in js bundle")
	}
	for _, m := range reXHRURL.FindAllStringSubmatch(js, -1) {
		add(m[2], strings.ToUpper(m[1]), KindAPI, SourceJSBundle, 0.8, "xhr open in js bundle")
	}
	for _, m := range reAxiosURL.FindAllStringSubmatch(js, -1) {
		if len(m) > 2 {
			add(m[2], strings.ToUpper(m[1]), KindAPI, SourceJSBundle, 0.75, "axios call in js bundle")
		}
	}
	for _, m := range reGraphQLPath.FindAllStringSubmatch(js, -1) {
		add(m[1], "POST", KindAPI, SourceGraphQL, 0.9, "graphql path in js bundle")
	}
	for _, m := range reWebSocketURL.FindAllStringSubmatch(js, -1) {
		add(m[1], "GET", KindAPI, SourceWebSocket, 0.85, "websocket constructor")
	}
	for _, m := range reDynamicImport.FindAllStringSubmatch(js, -1) {
		add(m[1], "GET", KindStatic, SourceJSBundle, 0.7, "dynamic import chunk")
	}
	for _, m := range reChunkManifest.FindAllStringSubmatch(js, -1) {
		add(m[1], "GET", KindStatic, SourceJSBundle, 0.65, "webpack chunk manifest")
	}
	for _, m := range reServiceWorker.FindAllStringSubmatch(js, -1) {
		add(m[1], "GET", KindStatic, SourceJSBundle, 0.7, "service worker registration")
	}

	routes := extractSPARoutes(js)
	for _, route := range routes {
		normalized := NormalizeRouteTemplate(route)
		kind := KindSPARoute
		if strings.HasPrefix(strings.ToLower(normalized), "/api/") {
			kind = KindAPI
		}
		add(normalized, "GET", kind, SourceSPARoute, 0.7, "spa router hint")
	}
	return out
}

func extractSPARoutes(js string) []string {
	var routes []string
	seen := map[string]struct{}{}
	addRoute := func(r string) {
		r = strings.TrimSpace(r)
		if !looksLikeRoute(r) {
			return
		}
		if _, ok := seen[r]; ok {
			return
		}
		seen[r] = struct{}{}
		routes = append(routes, r)
	}

	for _, m := range reRouterConfig.FindAllStringSubmatch(js, -1) {
		addRoute(m[1])
	}
	for _, m := range reReactRoute.FindAllStringSubmatch(js, -1) {
		addRoute(m[1])
	}
	for _, m := range reRouterCall.FindAllStringSubmatch(js, -1) {
		addRoute(m[1])
	}
	for _, m := range reApiRoute.FindAllStringSubmatch(js, -1) {
		addRoute(m[1])
	}
	if m := reNextRoute.FindStringSubmatch(js); len(m) > 1 {
		addRoute(m[1])
	}
	return routes
}

func looksLikeRoute(path string) bool {
	if len(path) < 2 || !strings.HasPrefix(path, "/") {
		return false
	}
	lower := strings.ToLower(path)

	// Reject static asset extensions
	for _, ext := range []string{
		".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp",
		".css", ".js", ".mjs", ".ts", ".tsx", ".jsx", ".map",
		".svg", ".woff", ".woff2", ".ttf", ".eot", ".otf",
		".mp3", ".mp4", ".wav", ".ogg", ".webm", ".avi",
		".pdf", ".zip", ".gz", ".tar", ".rar",
	} {
		if strings.HasSuffix(lower, ext) {
			return false
		}
	}

	// Reject regex patterns extracted from strings
	for _, ch := range []string{"^", "$", "\\", "+", "*", "(", ")", "|", "!"} {
		if strings.Contains(path, ch) {
			return false
		}
	}

	// Reject template/interpolation expressions
	if strings.Contains(path, "${") || strings.Contains(path, "<%") || strings.Contains(path, "%>") {
		return false
	}

	// Reject common noise / degenerate paths
	for _, noise := range []string{
		"//", "/../", "/./",
		"/node_modules/", "/bower_components/",
		"/dist/", "/build/", "/out/", "/tmp/",
		"/src/", "/lib/", "/vendor/",
		"/.git/", "/.svn/",
		"/undefined", "/null", "/NaN", "/true", "/false",
		"@", "#",
	} {
		if strings.Contains(path, noise) {
			return false
		}
	}

	// Reject framework internal / static asset directory prefixes
	for _, prefix := range []string{
		"/_next/", "/_nuxt/", "/_app/", "/__",
		"/static/", "/assets/", "/images/", "/img/",
		"/fonts/", "/media/", "/public/", "/icons/", "/locales/",
	} {
		if strings.HasPrefix(lower, prefix) {
			return false
		}
	}

	// Reject single segment that is too short
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(segments) == 1 && len(segments[0]) <= 2 {
		return false
	}

	// Require at least one letter
	hasLetter := false
	for _, r := range path[1:] {
		if unicode.IsLetter(r) {
			hasLetter = true
			break
		}
	}
	return hasLetter
}

// ExtractManifestAndServiceWorker parses HTML for web manifest references.
func ExtractManifestAndServiceWorker(baseURL, html string) []DiscoveredEndpoint {
	var out []DiscoveredEndpoint
	for _, m := range reManifest.FindAllStringSubmatch(html, -1) {
		resolved, err := ResolveReference(baseURL, m[1])
		if err == nil && resolved != "" {
			out = append(out, DiscoveredEndpoint{
				URL: resolved, Method: "GET", NormalizedURL: resolved, Kind: KindStatic, Source: SourceJSBundle, Confidence: 0.75, WhyDiscovered: "web manifest",
			})
		}
	}
	return out
}
