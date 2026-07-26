package fingerprint

import (
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/akha-security/akca/engine/internal/models"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

var (
	wappClient *wappalyzer.Wappalyze
	wappOnce   sync.Once
)

func getWappalyzer() *wappalyzer.Wappalyze {
	wappOnce.Do(func() {
		var err error
		wappClient, err = wappalyzer.New()
		if err != nil {
			// fallback/silent fail
			wappClient = nil
		}
	})
	return wappClient
}

var (
	rePageTitle      = regexp.MustCompile(`(?is)<title[^>]*>([^<]{1,200})</title>`)
	reMetaGenerator  = regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)
	reMetaGenerator2 = regexp.MustCompile(`(?i)<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator["']`)
	reWPVersion      = regexp.MustCompile(`(?i)WordPress\s+([\d.]+)`)
	reJQueryVer      = regexp.MustCompile(`(?i)jquery[.-]([\d.]+)(?:\.min)?\.js`)
	reBootstrapVer   = regexp.MustCompile(`(?i)bootstrap[.-]([\d.]+)(?:\.min)?\.(?:js|css)`)
	reReactVer       = regexp.MustCompile(`(?i)react[@.-]([\d.]+)(?:/|\.)`)
	reVueVer         = regexp.MustCompile(`(?i)vue[@.-]([\d.]+)(?:/|\.)`)
	reAngularVer     = regexp.MustCompile(`(?i)angular[@.-]([\d.]+)(?:/|\.)`)
	rePHPVer         = regexp.MustCompile(`(?i)php/([\d.]+)`)
	reNginxVer       = regexp.MustCompile(`(?i)nginx/([\d.]+)`)
	reApacheVer      = regexp.MustCompile(`(?i)apache/([\d.]+)`)
	reIISVer         = regexp.MustCompile(`(?i)microsoft-iis/([\d.]+)`)
	reOpenSSLVer     = regexp.MustCompile(`(?i)openssl/([\d.]+)`)
	reASPNetVer      = regexp.MustCompile(`(?i)x-aspnet-version:\s*([\d.]+)`)
	reExpressHdr     = regexp.MustCompile(`(?i)x-powered-by:\s*express`)
	reLaravelVer     = regexp.MustCompile(`(?i)laravel\s+v?([\d.]+)`)
	reDrupalMeta     = regexp.MustCompile(`(?i)drupal\s+([\d.]+)`)
	reNextBuild      = regexp.MustCompile(`(?i)"buildId"\s*:\s*"([^"]+)"`)
)

var securityHeaderNames = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"Content-Security-Policy-Report-Only",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Referrer-Policy",
	"Permissions-Policy",
	"Cross-Origin-Opener-Policy",
	"Cross-Origin-Resource-Policy",
	"Cross-Origin-Embedder-Policy",
	"X-XSS-Protection",
	"Expect-CT",
	"Public-Key-Pins",
}

// EnrichFingerprint adds versions, headers, cookies and page metadata to a tech fingerprint.
func EnrichFingerprint(fp *models.TechFingerprint, status int, headers map[string]string, body string) {
	if fp == nil {
		return
	}
	norm := normalizeHeaders(headers)
	fp.HTTPStatus = status
	fp.ResponseHeaders = pickInterestingHeaders(norm)
	fp.SecurityHeaders = auditSecurityHeaders(norm)
	fp.Cookies = parseSetCookies(headers)
	fp.PageTitle = extractPageTitle(body)
	fp.MetaGenerator = extractMetaGenerator(body)
	fp.TLSHints = tlsHintsFromHeaders(norm)
	fp.Components = extractComponents(norm, body, fp)

	// Backfill versioned backend from X-Powered-By when generic "PHP".
	if fp.BackendLanguage != "" && !strings.Contains(fp.BackendLanguage, "/") {
		if v := firstMatch(rePHPVer, headerVal(norm, "x-powered-by")); v != "" && strings.EqualFold(fp.BackendLanguage, "PHP") {
			fp.BackendLanguage = "PHP/" + v
		}
	}
}

func extractPageTitle(body string) string {
	if m := rePageTitle.FindStringSubmatch(body); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func extractMetaGenerator(body string) string {
	for _, re := range []*regexp.Regexp{reMetaGenerator, reMetaGenerator2} {
		if m := re.FindStringSubmatch(body); len(m) > 1 {
			return strings.TrimSpace(m[1])
		}
	}
	return ""
}

func pickInterestingHeaders(headers map[string]string) map[string]string {
	keys := []string{
		"server", "x-powered-by", "x-aspnet-version", "x-generator", "x-drupal-cache",
		"x-varnish", "via", "x-cache", "x-served-by", "x-amz-cf-id", "cf-ray",
		"content-type", "content-encoding", "set-cookie", "location",
		"x-frame-options", "strict-transport-security", "content-security-policy",
	}
	out := map[string]string{}
	for _, k := range keys {
		if v, ok := headers[k]; ok && strings.TrimSpace(v) != "" {
			out[k] = v
		}
	}
	return out
}

func auditSecurityHeaders(headers map[string]string) models.ReconSecurityAudit {
	audit := models.ReconSecurityAudit{Headers: map[string]string{}}
	var missing []string
	for _, name := range securityHeaderNames {
		lk := strings.ToLower(name)
		v, ok := headers[lk]
		if ok && strings.TrimSpace(v) != "" {
			audit.Headers[name] = v
			audit.PresentCount++
		} else {
			missing = append(missing, name)
		}
	}
	audit.Missing = missing
	audit.Score = audit.PresentCount * 100 / len(securityHeaderNames)
	return audit
}

func parseSetCookies(headers map[string]string) []models.ReconCookie {
	var raw []string
	for k, v := range headers {
		if strings.EqualFold(k, "Set-Cookie") {
			raw = append(raw, v)
		}
	}
	if len(raw) == 0 {
		if v := headers["set-cookie"]; v != "" {
			raw = append(raw, v)
		}
	}
	var out []models.ReconCookie
	for _, line := range raw {
		parts := strings.Split(line, ";")
		if len(parts) == 0 {
			continue
		}
		nv := strings.SplitN(strings.TrimSpace(parts[0]), "=", 2)
		if len(nv) < 1 || nv[0] == "" {
			continue
		}
		c := models.ReconCookie{Name: nv[0]}
		if len(nv) > 1 {
			c.ValuePreview = truncate(nv[1], 48)
		}
		lower := strings.ToLower(line)
		c.HttpOnly = strings.Contains(lower, "httponly")
		c.Secure = strings.Contains(lower, "secure")
		c.SameSite = cookieAttr(lower, "samesite")
		out = append(out, c)
	}
	return out
}

func cookieAttr(line, attr string) string {
	idx := strings.Index(strings.ToLower(line), attr+"=")
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(attr)+1:]
	if semi := strings.Index(rest, ";"); semi >= 0 {
		rest = rest[:semi]
	}
	return strings.TrimSpace(rest)
}

func tlsHintsFromHeaders(headers map[string]string) []string {
	var hints []string
	if v := headerVal(headers, "strict-transport-security"); v != "" {
		hints = append(hints, "HSTS: "+truncate(v, 80))
	}
	if v := headerVal(headers, "expect-ct"); v != "" {
		hints = append(hints, "Expect-CT: "+v)
	}
	return hints
}

func extractComponents(headers map[string]string, body string, fp *models.TechFingerprint) []models.TechComponent {
	combined := headersText(headers) + "\n" + body
	var comps []models.TechComponent
	add := func(name, version, category, source string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		for _, c := range comps {
			if strings.EqualFold(c.Name, name) {
				return
			}
		}
		comps = append(comps, models.TechComponent{
			Name: name, Version: version, Category: category, Source: source,
		})
	}

	// 1. Run wappalyzergo detection
	if wapp := getWappalyzer(); wapp != nil {
		hdr := make(http.Header)
		for k, v := range headers {
			hdr.Set(k, v)
		}
		res := wapp.Fingerprint(hdr, []byte(body))
		for tech := range res {
			add(tech, "", "wappalyzer", "Wappalyzer detection")
		}
	}

	if v := headerVal(headers, "server"); v != "" {
		if ver := firstMatch(reNginxVer, v); ver != "" {
			add("nginx", ver, "server", "Server header")
		} else if ver := firstMatch(reApacheVer, v); ver != "" {
			add("Apache", ver, "server", "Server header")
		} else if ver := firstMatch(reIISVer, v); ver != "" {
			add("Microsoft-IIS", ver, "server", "Server header")
		} else {
			add("Server", v, "server", "Server header")
		}
		if ver := firstMatch(reOpenSSLVer, v); ver != "" {
			add("OpenSSL", ver, "library", "Server header")
		}
	}
	if v := headerVal(headers, "x-powered-by"); v != "" {
		if ver := firstMatch(rePHPVer, v); ver != "" {
			add("PHP", ver, "backend", "X-Powered-By")
		} else {
			add("X-Powered-By", v, "backend", "header")
		}
	}
	if v := headerVal(headers, "x-aspnet-version"); v != "" {
		add("ASP.NET", v, "backend", "X-AspNet-Version")
	}
	if reExpressHdr.MatchString(combined) {
		add("Express", "", "framework", "X-Powered-By")
	}

	if fp.Framework != "" {
		add(fp.Framework, frameworkVersion(fp.Framework, combined), "framework", "fingerprint")
	}
	if fp.BackendLanguage != "" && !strings.HasPrefix(strings.ToLower(fp.BackendLanguage), "php") {
		add(fp.BackendLanguage, "", "backend", "fingerprint")
	} else if ver := firstMatch(rePHPVer, combined); ver != "" {
		add("PHP", ver, "backend", "response")
	}
	if fp.JSFramework != "" {
		add(fp.JSFramework, jsFrameworkVersion(fp.JSFramework, combined), "frontend", "fingerprint")
	}
	if fp.Database != "" {
		add(fp.Database, "", "database", "fingerprint")
	}

	if gen := extractMetaGenerator(body); gen != "" {
		if ver := firstMatch(reWPVersion, gen); ver != "" {
			add("WordPress", ver, "cms", "meta generator")
		} else if ver := firstMatch(reDrupalMeta, gen); ver != "" {
			add("Drupal", ver, "cms", "meta generator")
		} else {
			add("Generator", gen, "cms", "meta generator")
		}
	}
	if ver := firstMatch(reJQueryVer, combined); ver != "" {
		add("jQuery", ver, "frontend", "script")
	}
	if ver := firstMatch(reBootstrapVer, combined); ver != "" {
		add("Bootstrap", ver, "frontend", "asset")
	}
	if ver := firstMatch(reNextBuild, combined); ver != "" {
		add("Next.js build", ver, "frontend", "body")
	}

	return comps
}

func frameworkVersion(name, combined string) string {
	switch strings.ToLower(name) {
	case "wordpress":
		return firstMatch(reWPVersion, combined)
	case "drupal":
		return firstMatch(reDrupalMeta, combined)
	case "laravel":
		return firstMatch(reLaravelVer, combined)
	}
	return ""
}

func jsFrameworkVersion(name, combined string) string {
	switch strings.ToLower(name) {
	case "react":
		return firstMatch(reReactVer, combined)
	case "vue":
		return firstMatch(reVueVer, combined)
	case "angular":
		return firstMatch(reAngularVer, combined)
	}
	return ""
}

func headerVal(headers map[string]string, key string) string {
	return strings.TrimSpace(headers[strings.ToLower(key)])
}

func firstMatch(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
