package crawler

import (
	"net/url"
	"strings"
)

// ScoreEndpoint assigns higher priority to valuable endpoints. The score blends
// the discovery source, high-signal path keywords, file extensions, request
// method, presence of query parameters and confidence. Static/noise assets are
// penalized so the crawler spends its budget on interesting attack surface.
func ScoreEndpoint(ep DiscoveredEndpoint) int {
	score := 50
	path := strings.ToLower(ep.URL)

	score += sourceBonus(ep.Source)
	score += keywordBonus(path)
	score += extensionBonus(path)
	score += paramBonus(ep.URL)
	score -= depthPenalty(ep.Depth)

	if ep.Method != "GET" && ep.Method != "" {
		score += 12
	}
	switch {
	case ep.Confidence >= 0.9:
		score += 15
	case ep.Confidence >= 0.8:
		score += 10
	case ep.Confidence >= 0.6:
		score += 5
	}

	score -= staticAssetPenalty(path)

	if score < 1 {
		score = 1
	}
	if score > 200 {
		return 200
	}
	return score
}

func sourceBonus(src DiscoverySource) int {
	switch src {
	case SourceSeed, SourceSeedIngest:
		return 30
	case SourceGraphQL, SourceAPIDoc, SourceBrowserXHR, SourceWebSocket:
		return 35
	case SourceForm:
		return 28
	case SourceAST:
		return 24
	case SourceJSBundle, SourceSPARoute:
		return 20
	case SourceEventSource:
		return 18
	case SourceRobots, SourceSitemap:
		return 15
	case SourceDataAttr, SourceMetaRefresh, SourceCanonical:
		return 8
	case SourceHTMLComment:
		return 6
	}
	return 0
}

// highValueKeywords map URL substrings to a priority bonus. Authentication,
// admin, API, payment, file-handling and injection-prone surfaces score highest.
var highValueKeywords = []struct {
	word  string
	bonus int
}{
	// API surface
	{"/graphql", 38}, {"/graphiql", 36}, {"/api/", 30}, {"/rest/", 22}, {"/rpc", 22},
	{"/soap", 20}, {"/v1/", 15}, {"/v2/", 15}, {"/v3/", 15}, {"/openapi", 28},
	{"/swagger", 28}, {"/api-docs", 28}, {"/wp-json", 24}, {"/jsonrpc", 24},
	// Auth / identity
	{"/admin", 30}, {"/administrator", 30}, {"/login", 18}, {"/signin", 18},
	{"/logout", 10}, {"/register", 16}, {"/signup", 16}, {"/auth", 24},
	{"/oauth", 26}, {"/sso", 24}, {"/saml", 24}, {"/jwt", 22}, {"/token", 22},
	{"/session", 18}, {"/password", 22}, {"/reset", 18}, {"/forgot", 16},
	{"/account", 16}, {"/profile", 14}, {"/user", 14}, {"/users", 16},
	{"/me", 10}, {"/2fa", 18}, {"/mfa", 18}, {"/verify", 14},
	// Privilege / internal
	{"/internal", 24}, {"/private", 22}, {"/debug", 26}, {"/_debug", 26},
	{"/console", 24}, {"/dashboard", 18}, {"/manage", 20}, {"/superuser", 24},
	{"/root", 18}, {"/staff", 16}, {"/settings", 14}, {"/config", 24},
	{"/.git", 30}, {"/.env", 32}, {"/phpmyadmin", 30}, {"/actuator", 26},
	{"/metrics", 18}, {"/server-status", 24}, {"/status", 10},
	// Data / files (SSRF, LFI, upload, IDOR prone)
	{"/upload", 24}, {"/download", 22}, {"/file", 20}, {"/files", 20},
	{"/document", 16}, {"/export", 18}, {"/import", 18}, {"/backup", 26},
	{"/db", 20}, {"/sql", 22}, {"/query", 18}, {"/search", 14}, {"/report", 12},
	{"/proxy", 26}, {"/redirect", 24}, {"/render", 18}, {"/preview", 16},
	{"/fetch", 20}, {"/load", 14}, {"/include", 22}, {"/exec", 28}, {"/cmd", 28},
	{"/webhook", 18}, {"/callback", 18}, {"/payment", 22}, {"/checkout", 20},
	{"/invoice", 14}, {"/order", 14}, {"/cart", 12}, {"/key", 16},
	{"/secret", 22}, {"/credential", 24}, {"/.well-known", 8},
	// Common CMS / framework hot paths
	{"/wp-admin", 26}, {"/wp-login", 24}, {"/xmlrpc.php", 22}, {"/cgi-bin", 22},
	{"/id_rsa", 30}, {"/.aws", 30}, {"/.ssh", 30},
}

func keywordBonus(path string) int {
	bonus := 0
	for _, kw := range highValueKeywords {
		if strings.Contains(path, kw.word) {
			bonus += kw.bonus
		}
	}
	// Cap keyword contribution so a single noisy URL with many keywords does not
	// dominate the queue.
	if bonus > 80 {
		bonus = 80
	}
	return bonus
}

// interestingExtensions are script/handler/config/source extensions that often
// expose dynamic behaviour or sensitive content.
var interestingExtensions = map[string]int{
	".php": 16, ".asp": 16, ".aspx": 16, ".jsp": 16, ".jspx": 16,
	".do": 14, ".action": 14, ".cgi": 16, ".pl": 14, ".py": 12, ".rb": 12,
	".cfm": 14, ".phtml": 16, ".asmx": 16, ".ashx": 14,
	".json": 12, ".xml": 10, ".yaml": 12, ".yml": 12, ".conf": 16, ".ini": 14,
	".env": 30, ".log": 16, ".sql": 24, ".bak": 22, ".old": 18, ".swp": 18,
	".zip": 18, ".tar": 16, ".gz": 16, ".tgz": 16, ".7z": 16, ".rar": 16,
	".pem": 28, ".key": 26, ".p12": 24, ".pfx": 24, ".crt": 14,
}

func extensionBonus(path string) int {
	// Strip query/fragment before inspecting the extension.
	clean := path
	if i := strings.IndexAny(clean, "?#"); i >= 0 {
		clean = clean[:i]
	}
	dot := strings.LastIndex(clean, ".")
	if dot < 0 {
		return 0
	}
	ext := clean[dot:]
	if b, ok := interestingExtensions[ext]; ok {
		return b
	}
	return 0
}

// paramBonus rewards URLs that carry query parameters (injectable surface) and
// gives extra weight to identifier-like params that frequently enable IDOR.
func paramBonus(rawURL string) int {
	u, err := url.Parse(rawURL)
	if err != nil {
		return 0
	}
	q := u.Query()
	if len(q) == 0 {
		return 0
	}
	bonus := 8
	if len(q) > 1 {
		bonus += 4
	}
	for name := range q {
		ln := strings.ToLower(name)
		switch {
		case ln == "id" || strings.HasSuffix(ln, "_id") || strings.HasSuffix(ln, "id"):
			bonus += 8
		case strings.Contains(ln, "url") || strings.Contains(ln, "redirect") ||
			strings.Contains(ln, "next") || strings.Contains(ln, "return") ||
			strings.Contains(ln, "callback") || strings.Contains(ln, "dest"):
			bonus += 10
		case strings.Contains(ln, "file") || strings.Contains(ln, "path") ||
			strings.Contains(ln, "page") || strings.Contains(ln, "template") ||
			strings.Contains(ln, "include") || strings.Contains(ln, "load"):
			bonus += 9
		case strings.Contains(ln, "q") || strings.Contains(ln, "search") ||
			strings.Contains(ln, "query") || strings.Contains(ln, "keyword"):
			bonus += 6
		}
	}
	if bonus > 30 {
		bonus = 30
	}
	return bonus
}

// staticNoiseExtensions are pure static assets that rarely yield findings.
var staticNoiseExtensions = []string{
	".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
	".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".webm", ".mp3", ".wav",
	".pdf", ".avif",
}

func staticAssetPenalty(path string) int {
	clean := path
	if i := strings.IndexAny(clean, "?#"); i >= 0 {
		clean = clean[:i]
	}
	for _, ext := range staticNoiseExtensions {
		if strings.HasSuffix(clean, ext) {
			return 12
		}
	}
	return 0
}

func depthPenalty(depth int) int {
	if depth <= 1 {
		return 0
	}
	penalty := (depth - 1) * 8
	if penalty > 40 {
		return 40
	}
	return penalty
}
