package crawler

import (
	"regexp"
	"strings"
)

var (
	reFetchURL      = regexp.MustCompile(`(?i)fetch\s*\(\s*["']([^"']+)["']`)
	reXHRURL        = regexp.MustCompile(`(?i)\.open\s*\(\s*["'](GET|POST|PUT|DELETE|PATCH)["']\s*,\s*["']([^"']+)["']`)
	reAxiosURL      = regexp.MustCompile(`(?i)axios\.(get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']`)
	reGraphQLPath   = regexp.MustCompile(`(?i)["'](/graphql[^"']*)["']`)
	reWebSocketURL  = regexp.MustCompile(`(?i)new\s+WebSocket\s*\(\s*["']([^"']+)["']`)
	reDynamicImport = regexp.MustCompile(`(?i)import\s*\(\s*["']([^"']+)["']\s*\)`)
	reChunkManifest = regexp.MustCompile(`(?i)["']([^"']+\.chunk\.js)["']`)
	reRouterPath    = regexp.MustCompile(`(?i)["'](/[a-zA-Z0-9_./:?*\[\]{}-]+)["']`)
	reNextRoute     = regexp.MustCompile(`(?i)__NEXT_DATA__[^}]*"pathname"\s*:\s*"([^"]+)"`)
	reServiceWorker = regexp.MustCompile(`(?i)navigator\.serviceWorker\.register\s*\(\s*["']([^"']+)["']`)
	reManifest      = regexp.MustCompile(`(?i)<link[^>]+rel=["']manifest["'][^>]+href=["']([^"']+)["']`)
)

// ExtractFromJSBundle extracts endpoints from minified or normal JavaScript.
func ExtractFromJSBundle(baseURL, js string) []DiscoveredEndpoint {
	var out []DiscoveredEndpoint
	add := func(raw, method string, source DiscoverySource, confidence float64, why string) {
		resolved, err := ResolveReference(baseURL, raw)
		if err != nil || resolved == "" {
			return
		}
		if strings.Contains(resolved, "graphql") {
			source = SourceGraphQL
		}
		if strings.HasPrefix(strings.ToLower(resolved), "ws://") || strings.HasPrefix(strings.ToLower(resolved), "wss://") {
			source = SourceWebSocket
		}
		out = append(out, DiscoveredEndpoint{
			URL: resolved, Method: method, Source: source, Confidence: confidence, WhyDiscovered: why,
		})
	}

	for _, m := range reFetchURL.FindAllStringSubmatch(js, -1) {
		add(m[1], "GET", SourceJSBundle, 0.8, "fetch() in js bundle")
	}
	for _, m := range reXHRURL.FindAllStringSubmatch(js, -1) {
		add(m[2], strings.ToUpper(m[1]), SourceJSBundle, 0.8, "xhr open in js bundle")
	}
	for _, m := range reAxiosURL.FindAllStringSubmatch(js, -1) {
		if len(m) > 2 {
			add(m[2], strings.ToUpper(m[1]), SourceJSBundle, 0.75, "axios call in js bundle")
		}
	}
	for _, m := range reGraphQLPath.FindAllStringSubmatch(js, -1) {
		add(m[1], "POST", SourceGraphQL, 0.9, "graphql path in js bundle")
	}
	for _, m := range reWebSocketURL.FindAllStringSubmatch(js, -1) {
		add(m[1], "GET", SourceWebSocket, 0.85, "websocket constructor")
	}
	for _, m := range reDynamicImport.FindAllStringSubmatch(js, -1) {
		add(m[1], "GET", SourceJSBundle, 0.7, "dynamic import chunk")
	}
	for _, m := range reChunkManifest.FindAllStringSubmatch(js, -1) {
		add(m[1], "GET", SourceJSBundle, 0.65, "webpack chunk manifest")
	}
	for _, m := range reServiceWorker.FindAllStringSubmatch(js, -1) {
		add(m[1], "GET", SourceJSBundle, 0.7, "service worker registration")
	}

	routes := extractSPARoutes(js)
	for _, route := range routes {
		normalized := NormalizeRouteTemplate(route)
		add(normalized, "GET", SourceSPARoute, 0.7, "spa router hint")
	}
	return out
}

func extractSPARoutes(js string) []string {
	var routes []string
	seen := map[string]struct{}{}
	for _, m := range reRouterPath.FindAllStringSubmatch(js, -1) {
		r := m[1]
		if !looksLikeRoute(r) {
			continue
		}
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		routes = append(routes, r)
	}
	if m := reNextRoute.FindStringSubmatch(js); len(m) > 1 {
		routes = append(routes, m[1])
	}
	return routes
}

func looksLikeRoute(path string) bool {
	if len(path) < 2 || !strings.HasPrefix(path, "/") {
		return false
	}
	lower := strings.ToLower(path)
	bad := []string{".png", ".jpg", ".css", ".js", ".svg", ".woff", ".gif"}
	for _, ext := range bad {
		if strings.HasSuffix(lower, ext) {
			return false
		}
	}
	return true
}

// ExtractManifestAndServiceWorker parses HTML for web manifest references.
func ExtractManifestAndServiceWorker(baseURL, html string) []DiscoveredEndpoint {
	var out []DiscoveredEndpoint
	for _, m := range reManifest.FindAllStringSubmatch(html, -1) {
		resolved, err := ResolveReference(baseURL, m[1])
		if err == nil && resolved != "" {
			out = append(out, DiscoveredEndpoint{
				URL: resolved, Method: "GET", Source: SourceJSBundle, Confidence: 0.75, WhyDiscovered: "web manifest",
			})
		}
	}
	return out
}
