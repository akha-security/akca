package jsanalyzer

import (
	"regexp"
	"strings"
	"unicode"
)

var (
	reFetch       = regexp.MustCompile(`(?i)fetch\s*\(\s*["']([^"']+)["']`)
	reXHR         = regexp.MustCompile(`(?i)\.open\s*\(\s*["'](GET|POST|PUT|DELETE|PATCH)["']\s*,\s*["']([^"']+)["']`)
	reAxios       = regexp.MustCompile(`(?i)axios\.(get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']`)
	reGraphQL     = regexp.MustCompile(`(?i)["'](/graphql[^"']*?)["']`)
	reWebSocket   = regexp.MustCompile(`(?i)new\s+WebSocket\s*\(\s*["']([^"']+)["']`)
	reEventSource = regexp.MustCompile(`(?i)new\s+EventSource\s*\(\s*["']([^"']+)["']`)
	reDynamicImp  = regexp.MustCompile(`(?i)import\s*\(\s*["']([^"']+)["']\s*\)`)
	reChunk       = regexp.MustCompile(`(?i)["']([^"']+\.chunk\.js)["']`)
	// Tightened: require at least one letter after / and only allow path-like chars.
	reRoutes           = regexp.MustCompile(`["'](/[a-zA-Z][a-zA-Z0-9_./:-]{1,120})["']`)
	reNextData         = regexp.MustCompile(`(?i)__NEXT_DATA__[\s\S]*?"pathname"\s*:\s*"([^"]+)"`)
	reNuxt             = regexp.MustCompile(`(?i)window\.__NUXT__`)
	reSvelteKit        = regexp.MustCompile(`(?i)__sveltekit_[a-z0-9]+`)
	reServiceWorker    = regexp.MustCompile(`(?i)navigator\.serviceWorker\.register\s*\(\s*["']([^"']+)["']`)
	reConfigURL        = regexp.MustCompile(`(?i)(?:base_?url|api_?url|api_?base|api_?host|endpoint|gateway_?url|graphql_?(?:uri|url|endpoint))\s*[:=]\s*["']([^"']+)["']`)
	reApiRoute         = regexp.MustCompile(`(?i)["'](/api/(?:v[0-9]+/|v[0-9]+)?[a-zA-Z0-9_./:-]{2,100})["']`)
	reRouterPath       = regexp.MustCompile(`(?i)(?:path|route)\s*:\s*["'](/[a-zA-Z][a-zA-Z0-9_./:-]{1,100})["']`)
	reTemplateRoute    = regexp.MustCompile("`(/[a-zA-Z0-9_./:-]*\\$\\{[^}]+\\}[a-zA-Z0-9_./:-]*)`")
	reParamPlaceholder = regexp.MustCompile(`\$\{[^}]+\}`)
	reViteAsset        = regexp.MustCompile(`(?i)["'](/assets/[a-zA-Z0-9_-]+\.js)["']`)
	reReactRoute       = regexp.MustCompile(`(?i)<(?:Route|NavLink|Link)\s+[^>]*to=["'](/[^"']+)["']|<Route\s+[^>]*path=["'](/[^"']+)["']`)
)

// ExtractHeuristic uses regex patterns for minified or syntactically broken JavaScript.
func ExtractHeuristic(js string) []ExtractedEndpoint {
	var out []ExtractedEndpoint
	add := func(raw, method, source, why string) {
		conf := ScoreEndpoint(raw, "heuristic", method)
		out = append(out, ExtractedEndpoint{
			URL: raw, Method: method, Template: NormalizeTemplate(raw),
			Source: source, Extraction: "heuristic", Confidence: conf, Why: why,
		})
	}

	for _, m := range reFetch.FindAllStringSubmatch(js, -1) {
		add(m[1], "GET", "fetch", "heuristic fetch()")
	}
	for _, m := range reXHR.FindAllStringSubmatch(js, -1) {
		add(m[2], strings.ToUpper(m[1]), "xhr", "heuristic xhr.open")
	}
	for _, m := range reAxios.FindAllStringSubmatch(js, -1) {
		add(m[2], strings.ToUpper(m[1]), "axios", "heuristic axios")
	}
	for _, m := range reGraphQL.FindAllStringSubmatch(js, -1) {
		add(m[1], "POST", "graphql", "heuristic graphql path")
	}
	for _, m := range reWebSocket.FindAllStringSubmatch(js, -1) {
		add(m[1], "GET", "websocket", "heuristic websocket")
	}
	for _, m := range reEventSource.FindAllStringSubmatch(js, -1) {
		add(m[1], "GET", "eventsource", "heuristic eventsource")
	}
	for _, m := range reDynamicImp.FindAllStringSubmatch(js, -1) {
		add(m[1], "GET", "dynamic_import", "heuristic dynamic import")
	}
	for _, m := range reChunk.FindAllStringSubmatch(js, -1) {
		add(m[1], "GET", "chunk", "heuristic chunk manifest")
	}
	for _, m := range reViteAsset.FindAllStringSubmatch(js, -1) {
		add(m[1], "GET", "vite_asset", "heuristic vite asset chunk")
	}
	for _, m := range reServiceWorker.FindAllStringSubmatch(js, -1) {
		add(m[1], "GET", "service_worker", "heuristic service worker")
	}
	for _, m := range reConfigURL.FindAllStringSubmatch(js, -1) {
		v := strings.TrimSpace(m[1])
		if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") || strings.HasPrefix(v, "/") {
			add(v, "GET", "config", "heuristic API base/config URL")
		}
	}
	for _, m := range reTemplateRoute.FindAllStringSubmatch(js, -1) {
		// Replace ${param} with {param} to normalize template literals
		tRoute := reParamPlaceholder.ReplaceAllString(m[1], "{param}")
		if routeLooksValid(tRoute) {
			add(NormalizeTemplate(tRoute), "GET", "template_literal", "heuristic template literal route")
		}
	}
	for _, m := range reReactRoute.FindAllStringSubmatch(js, -1) {
		rPath := m[1]
		if rPath == "" {
			rPath = m[2]
		}
		if routeLooksValid(rPath) {
			add(NormalizeTemplate(rPath), "GET", "react_route", "heuristic react route path")
		}
	}
	for _, m := range reApiRoute.FindAllStringSubmatch(js, -1) {
		if routeLooksValid(m[1]) {
			add(NormalizeTemplate(m[1]), "GET", "api_route", "heuristic api route")
		}
	}
	for _, m := range reRouterPath.FindAllStringSubmatch(js, -1) {
		if routeLooksValid(m[1]) {
			add(NormalizeTemplate(m[1]), "GET", "spa_router", "heuristic spa router definition")
		}
	}
	for _, m := range reRoutes.FindAllStringSubmatch(js, -1) {
		if routeLooksValid(m[1]) {
			add(NormalizeTemplate(m[1]), "GET", "router", "heuristic router path")
		}
	}
	if m := reNextData.FindStringSubmatch(js); len(m) > 1 {
		add(m[1], "GET", "next_manifest", "next.js pathname")
	}
	if reNuxt.MatchString(js) {
		add("/_nuxt/", "GET", "nuxt_manifest", "nuxt runtime marker")
	}
	if reSvelteKit.MatchString(js) {
		add("/_app/", "GET", "sveltekit_manifest", "sveltekit runtime marker")
	}
	return out
}

// routeLooksValid applies strict validation to reject JS artifacts that look
// like paths but are actually regex patterns, CSS selectors, template
// expressions, internal framework paths, or other noise.
func routeLooksValid(path string) bool {
	if len(path) < 3 || !strings.HasPrefix(path, "/") {
		return false
	}

	lower := strings.ToLower(path)

	// ── Reject static asset extensions ──
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

	// ── Reject regex-like patterns ──
	// Paths containing regex metacharacters are almost certainly regex patterns
	// extracted from string literals, not real API endpoints.
	for _, ch := range []string{"^", "$", "\\", "+", "*", "(", ")", "[", "]", "{", "}", "|", "?", "!"} {
		if strings.Contains(path, ch) {
			return false
		}
	}

	// ── Reject template/interpolation expressions ──
	if strings.Contains(path, "${") || strings.Contains(path, "<%") || strings.Contains(path, "%>") {
		return false
	}

	// ── Reject common JS/CSS/framework artifacts ──
	for _, noise := range []string{
		"//", "/../", "/./", // degenerate paths
		"/node_modules/", "/bower_components/", // package manager
		"/dist/", "/build/", "/out/", "/tmp/", // build artifacts
		"/src/", "/lib/", "/vendor/", // source dirs (not API)
		"/.git/", "/.svn/", // VCS
		"/undefined", "/null", "/NaN", "/true", "/false", // JS literal noise
		"@", "#", "=", // query/fragment/selector noise
	} {
		if strings.Contains(path, noise) {
			return false
		}
	}

	// ── Reject paths that start with framework-internal prefixes ──
	for _, prefix := range []string{
		"/_next/", "/_nuxt/", "/_app/", "/__", // framework internal routes
		"/static/", "/assets/", "/images/", "/img/", // static resource dirs
		"/fonts/", "/media/", "/public/",
	} {
		if strings.HasPrefix(lower, prefix) {
			return false
		}
	}

	// ── Reject single-segment paths that are too short or too generic ──
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(segments) == 1 && len(segments[0]) <= 2 {
		return false // e.g. "/a", "/x" — almost certainly noise
	}

	// ── Require at least one letter (rejects e.g. "/123/456") ──
	hasLetter := false
	for _, r := range path[1:] { // skip leading /
		if unicode.IsLetter(r) {
			hasLetter = true
			break
		}
	}
	if !hasLetter {
		return false
	}

	// ── Reject paths with too many colons (template params like /:a/:b/:c/:d) ──
	if strings.Count(path, ":") > 3 {
		return false
	}

	return true
}
