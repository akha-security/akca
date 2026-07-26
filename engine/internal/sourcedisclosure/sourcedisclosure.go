package sourcedisclosure

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/akha-security/akca/engine/internal/secretscan"
)

// Finding is a semantic leak inside disclosed source code.
type Finding struct {
	Kind       string  `json:"kind"`
	Match      string  `json:"match"`
	Severity   string  `json:"severity"`
	Confidence float64 `json:"confidence"`
}

var (
	internalIPRe   = regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	internalHostRe = regexp.MustCompile(`(?i)\b(?:internal|staging|dev|corp|local)\.[a-z0-9.\-]+\.(?:local|internal|lan|corp)\b`)
	debugLogicRe   = regexp.MustCompile(`(?i)(?:if\s*\(\s*(?:debug|is_debug|app_debug|dev_mode|staging)\s*(?:==|===|!=)\s*(?:true|1|'1'|"1"|'staging'|"staging")\s*\)|APP_DEBUG\s*=\s*true|DEBUG\s*=\s*True|env\s*==\s*['"]staging['"])`)
	jwtSecretRe    = regexp.MustCompile(`(?i)(?:jwt[_\-]?secret|session[_\-]?secret|signing[_\-]?key|cookie[_\-]?secret)\s*[:=]\s*['"]([^'"]{8,})['"]`)
)

// SourceSuffixes are backup/disclosure extensions to probe relative to a URL path.
var SourceSuffixes = []string{
	".bak", ".old", ".save", ".swp", ".tmp", "~",
	".php.bak", ".php.old", ".php~", ".php.swp",
	".py.bak", ".js.map", ".css.map",
	".conf.bak", ".config.bak", ".env.bak", ".env.old",
}

// SourcePathHints are common disclosed source/config paths.
var SourcePathHints = []string{
	"/config.php", "/config.php.bak", "/wp-config.php.bak",
	"/settings.py", "/settings.py.bak", "/web.config", "/web.config.bak",
	"/application.yml.bak", "/database.yml", "/.env.backup",
}

// LooksLikeSourceCode reports whether a response body resembles raw source.
func LooksLikeSourceCode(body, contentType string) bool {
	if len(body) < 20 {
		return false
	}
	lower := strings.ToLower(contentType + " " + body[:min(512, len(body))])
	markers := []string{
		"<?php", "<?=", "#!/usr/bin", "import ", "def ", "function ",
		"class ", "package ", "namespace ", "const ", "module.exports",
		"-----BEGIN", "DB_HOST", "mysql://", "postgres://",
	}
	for _, m := range markers {
		if strings.Contains(lower, strings.ToLower(m)) {
			return true
		}
	}
	return false
}

// Analyze performs semantic analysis on disclosed source content.
func Analyze(body string) []Finding {
	if body == "" {
		return nil
	}
	var out []Finding
	seen := map[string]struct{}{}
	add := func(kind, match, severity string, conf float64) {
		key := kind + "|" + match
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, Finding{Kind: kind, Match: match, Severity: severity, Confidence: conf})
	}

	for _, m := range secretscan.Detect(body) {
		sev := "high"
		if m.Confidence < 0.7 {
			sev = "medium"
		}
		add("secret_"+m.Kind, m.Redacted, sev, m.Confidence)
	}

	for _, ip := range internalIPRe.FindAllString(body, 8) {
		add("internal_ip", ip, "medium", 0.75)
	}
	for _, h := range internalHostRe.FindAllString(body, 8) {
		add("internal_hostname", h, "medium", 0.7)
	}
	if m := debugLogicRe.FindString(body); m != "" {
		add("debug_logic", truncate(m, 120), "medium", 0.8)
	}
	if m := jwtSecretRe.FindStringSubmatch(body); len(m) > 1 {
		add("jwt_secret", secretscan.Redact(m[1]), "critical", 0.9)
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// CandidateURLs builds backup/source disclosure URLs from a base endpoint.
func CandidateURLs(baseURL string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(u string) {
		if u == "" {
			return
		}
		if _, ok := seen[u]; ok {
			return
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}

	for _, hint := range SourcePathHints {
		add(joinURL(baseURL, hint))
	}

	lower := strings.ToLower(baseURL)
	for _, suf := range SourceSuffixes {
		add(joinURL(baseURL, suf))
	}
	if strings.HasSuffix(lower, ".js") {
		add(joinURL(baseURL, ".map"))
	}
	if strings.Contains(lower, ".php") {
		add(joinURL(baseURL, ".bak"))
		add(joinURL(baseURL, "~"))
	}
	return out
}

func joinURL(base, path string) string {
	parsed, err := url.Parse(base)
	if err != nil {
		base = strings.TrimRight(base, "/")
		if strings.HasSuffix(strings.ToLower(base), strings.ToLower(path)) {
			return base
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		return base + path
	}

	clone := *parsed
	if strings.HasPrefix(path, "/") {
		if strings.HasSuffix(strings.ToLower(clone.Path), strings.ToLower(path)) {
			return clone.String()
		}
		clone.Path = path
		clone.RawQuery = ""
		clone.Fragment = ""
		return clone.String()
	}

	if strings.HasSuffix(strings.ToLower(clone.Path), strings.ToLower(path)) {
		return clone.String()
	}
	if clone.Path == "" {
		clone.Path = "/"
	}
	clone.Path += path
	return clone.String()
}
