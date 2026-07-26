package fingerprint

import (
	"context"
	"net/http"
	"regexp"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/models"
)

var (
	reReact    = regexp.MustCompile(`(?i)react|__NEXT_DATA__|_next/static`)
	reNext     = regexp.MustCompile(`(?i)__NEXT_DATA__|_next/static|next\.js`)
	reNuxt     = regexp.MustCompile(`(?i)__NUXT__|_nuxt/|nuxt\.js`)
	reVue      = regexp.MustCompile(`(?i)vue\.js|vue-router|__VUE__|data-v-`)
	reAngular  = regexp.MustCompile(`(?i)ng-version|angular|ng-app`)
	reSvelte   = regexp.MustCompile(`(?i)svelte|__svelte`)
	reJQuery   = regexp.MustCompile(`(?i)jquery`)
	reLaravel  = regexp.MustCompile(`(?i)laravel_session|XSRF-TOKEN|laravel`)
	reSymfony  = regexp.MustCompile(`(?i)symfony|sf_redirect|_profiler`)
	reCodeIgn  = regexp.MustCompile(`(?i)ci_session|codeigniter`)
	reDjango   = regexp.MustCompile(`(?i)csrftoken|django|__admin__`)
	reFlask    = regexp.MustCompile(`(?i)flask|werkzeug`)
	reRails    = regexp.MustCompile(`(?i)_rails|csrf-token|x-runtime`)
	reSpring   = regexp.MustCompile(`(?i)spring|jsessionid|x-application-context`)
	reASPNet   = regexp.MustCompile(`(?i)asp\.net|__VIEWSTATE|aspxauth`)
	reExpress  = regexp.MustCompile(`(?i)express|connect\.sid`)
	rePHP      = regexp.MustCompile(`(?i)PHPSESSID|x-powered-by:\s*php|\.php`)
	reWordPress = regexp.MustCompile(`(?i)wp-content|wp-includes|wordpress|wp-json`)
	reDrupal   = regexp.MustCompile(`(?i)drupal|sites/default|x-drupal`)
	reJoomla   = regexp.MustCompile(`(?i)joomla|/media/jui/`)
	reMySQL    = regexp.MustCompile(`(?i)mysql|mariadb`)
	rePostgres = regexp.MustCompile(`(?i)postgresql|postgres`)
	reMongo    = regexp.MustCompile(`(?i)mongodb|mongoose`)
	reRedis    = regexp.MustCompile(`(?i)redis`)
	reMSSQL    = regexp.MustCompile(`(?i)mssql|sql server|sqlserver`)
	reOracle   = regexp.MustCompile(`(?i)\boracle\b|ora-[0-9]`)
)

type TechFingerprinter struct {
	client *httpclient.Client
}

func NewTechFingerprinter(client *httpclient.Client) *TechFingerprinter {
	return &TechFingerprinter{client: client}
}

func (t *TechFingerprinter) Fingerprint(ctx context.Context, targetURL string) (models.TechFingerprint, error) {
	fp := models.TechFingerprint{
		Host:       hostFromURL(targetURL),
		DetectedAt: models.NowRFC3339(),
	}

	rr, err := t.client.Do(ctx, http.MethodGet, targetURL, nil, nil)
	if err != nil {
		return fp, err
	}

	headers := normalizeHeaders(rr.Response.Headers)
	body := rr.Response.Body
	combined := strings.ToLower(headersText(headers) + "\n" + body)

	fp.ServerCDN = detectServerCDN(headers, combined)
	fp.BackendLanguage = detectBackend(headers, combined)
	fp.Framework = detectFramework(headers, combined)
	fp.Database = detectDatabase(combined)
	fp.JSFramework = detectJSFramework(combined)
	fp.Hints = collectHints(fp)
	if ct, ok := headers["content-type"]; ok {
		fp.ContentType = ct
	}
	EnrichFingerprint(&fp, rr.Response.StatusCode, headers, body)
	return fp, nil
}

func detectServerCDN(headers map[string]string, combined string) string {
	var parts []string
	if server, ok := headers["server"]; ok && server != "" {
		parts = append(parts, server)
	}
	for vendor, needle := range map[string]string{
		"cloudflare": "cloudflare", "akamai": "akamai", "fastly": "fastly",
		"cloudfront": "cloudfront", "nginx": "nginx", "apache": "apache",
		"iis": "microsoft-iis", "litespeed": "litespeed", "tomcat": "tomcat",
		"caddy": "caddy", "envoy": "envoy", "vercel": "vercel", "netlify": "netlify",
	} {
		if strings.Contains(combined, needle) && !containsFold(parts, vendor) {
			parts = append(parts, vendor)
		}
	}
	return strings.Join(parts, ", ")
}

func detectBackend(headers map[string]string, combined string) string {
	if powered, ok := headers["x-powered-by"]; ok && powered != "" {
		return strings.TrimSpace(powered)
	}
	switch {
	case rePHP.MatchString(combined):
		return "PHP"
	case reASPNet.MatchString(combined):
		return "ASP.NET"
	case reExpress.MatchString(combined) || strings.Contains(combined, "node"):
		return "Node.js"
	case reFlask.MatchString(combined) || strings.Contains(combined, "python") ||
		strings.Contains(combined, "gunicorn") || strings.Contains(combined, "uwsgi") || strings.Contains(combined, "wsgi"):
		return "Python"
	case reRails.MatchString(combined) || strings.Contains(combined, "ruby") || strings.Contains(combined, "puma"):
		return "Ruby"
	case reSpring.MatchString(combined) || strings.Contains(combined, "java") ||
		strings.Contains(combined, "servlet") || strings.Contains(combined, "jsp"):
		return "Java"
	case strings.Contains(combined, "go ") || strings.Contains(combined, "golang") || strings.Contains(combined, "gin"):
		return "Go"
	}
	return ""
}

func detectFramework(headers map[string]string, combined string) string {
	switch {
	case reWordPress.MatchString(combined):
		return "WordPress"
	case reDrupal.MatchString(combined):
		return "Drupal"
	case reJoomla.MatchString(combined):
		return "Joomla"
	case reLaravel.MatchString(combined):
		return "Laravel"
	case reSymfony.MatchString(combined):
		return "Symfony"
	case reCodeIgn.MatchString(combined):
		return "CodeIgniter"
	case reDjango.MatchString(combined):
		return "Django"
	case reFlask.MatchString(combined):
		return "Flask"
	case reRails.MatchString(combined):
		return "Rails"
	case reSpring.MatchString(combined):
		return "Spring"
	case reExpress.MatchString(combined):
		return "Express"
	case reASPNet.MatchString(combined):
		return "ASP.NET"
	}
	if _, ok := headers["x-drupal-cache"]; ok {
		return "Drupal"
	}
	return ""
}

func detectDatabase(combined string) string {
	switch {
	case reMySQL.MatchString(combined):
		return "MySQL"
	case rePostgres.MatchString(combined):
		return "PostgreSQL"
	case reMSSQL.MatchString(combined):
		return "MSSQL"
	case reOracle.MatchString(combined):
		return "Oracle"
	case reMongo.MatchString(combined):
		return "MongoDB"
	case reRedis.MatchString(combined):
		return "Redis"
	case strings.Contains(combined, "sqlite"):
		return "SQLite"
	}
	return ""
}

func detectJSFramework(combined string) string {
	switch {
	case reReact.MatchString(combined):
		return "React"
	case reNuxt.MatchString(combined):
		return "Nuxt"
	case reNext.MatchString(combined):
		return "Next.js"
	case reVue.MatchString(combined):
		return "Vue"
	case reAngular.MatchString(combined):
		return "Angular"
	case reSvelte.MatchString(combined):
		return "Svelte"
	case reJQuery.MatchString(combined):
		return "jQuery"
	}
	return ""
}

func containsFold(items []string, v string) bool {
	for _, it := range items {
		if strings.EqualFold(it, v) {
			return true
		}
	}
	return false
}

func collectHints(fp models.TechFingerprint) []string {
	var hints []string
	for _, pair := range []struct{ k, v string }{
		{"backend", fp.BackendLanguage},
		{"framework", fp.Framework},
		{"database", fp.Database},
		{"server", fp.ServerCDN},
		{"js", fp.JSFramework},
	} {
		if pair.v != "" {
			hints = append(hints, pair.k+":"+pair.v)
		}
	}
	return hints
}

func normalizeHeaders(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		out[strings.ToLower(k)] = v
	}
	return out
}

func headersText(headers map[string]string) string {
	var b strings.Builder
	for k, v := range headers {
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(v)
		b.WriteString("\n")
	}
	return b.String()
}

func hostFromURL(raw string) string {
	parts := strings.Split(strings.TrimPrefix(strings.TrimPrefix(raw, "https://"), "http://"), "/")
	if len(parts) == 0 {
		return raw
	}
	return parts[0]
}
