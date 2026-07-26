package fuzzing

import (
	"net/url"
	"strings"
)

// BuildTasks builds the default, technology-agnostic fuzzing task set.
func BuildTasks(baseURL string) []FuzzTask {
	return BuildTasksForTech(baseURL, nil)
}

// BuildTasksForTech builds the default task set plus paths tailored to the
// detected technology stack (hints come from the tech fingerprint, e.g.
// "framework:Laravel", "backend:PHP", "server:nginx"). Tech-aware probing keeps
// the request budget focused on paths that actually exist for the target.
func BuildTasksForTech(baseURL string, hints []string) []FuzzTask {
	base := strings.TrimRight(baseURL, "/")
	var tasks []FuzzTask
	seen := map[string]struct{}{}
	add := func(path string, cat Category) {
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		tasks = append(tasks, FuzzTask{
			URL: base + path, Method: "GET", Category: cat, Path: path,
		})
	}

	for _, p := range generalPaths {
		add(p, CategoryGeneral)
	}
	for _, p := range archivePaths {
		add(p, CategoryArchive)
	}
	for _, p := range adminPaths {
		add(p, CategoryAdmin)
	}
	for _, p := range artifactPaths {
		add(p, CategoryArtifact)
	}
	for _, p := range frameworkPaths {
		add(p, CategoryFramework)
	}
	for _, p := range apiPaths {
		add(p, CategoryAPI)
	}
	for _, p := range configPaths {
		add(p, CategoryConfig)
	}
	for _, p := range actuatorPaths {
		if strings.Contains(p, "shutdown") {
			continue
		}
		add(p, CategoryActuator)
	}

	for _, p := range techSpecificPaths(hints) {
		add(p, CategoryFramework)
	}
	return tasks
}

var generalPaths = []string{
	"/robots.txt", "/sitemap.xml", "/sitemap_index.xml", "/crossdomain.xml",
	"/clientaccesspolicy.xml", "/security.txt", "/.well-known/security.txt",
	"/.well-known/change-password", "/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server", "/.well-known/jwks.json",
	"/.well-known/assetlinks.json", "/.well-known/apple-app-site-association",
	"/humans.txt", "/browserconfig.xml", "/ads.txt", "/app-ads.txt",
	"/manifest.json", "/manifest.webmanifest", "/service-worker.js",
}

var archivePaths = []string{
	"/backup.zip", "/backup.tar.gz", "/backup.tar", "/backup.rar", "/backup.7z",
	"/site.zip", "/www.zip", "/web.zip", "/html.zip", "/public_html.zip",
	"/wwwroot.zip", "/source.zip", "/src.zip", "/archive.zip", "/old.zip",
	"/app.zip", "/release.zip", "/dist.zip", "/backup.tar.xz",
	"/db.sql", "/dump.sql", "/database.sql", "/backup.sql", "/backup.sql.gz",
	"/db_backup.sql", "/mysql.sql", "/data.sql", "/users.sql", "/export.sql",
	"/prod.sql", "/backup.dump", "/database.sqlite", "/db.sqlite3",
	"/backup.bak", "/site.bak", "/index.php.bak", "/config.php.bak", "/.DS_Store",
}

var adminPaths = []string{
	"/admin", "/admin/", "/admin/login", "/admin/index.php", "/admin.php",
	"/administrator", "/administrator/", "/adminpanel", "/admin-console",
	"/manage", "/manager", "/management", "/dashboard", "/console", "/portal",
	"/cpanel", "/webadmin", "/sysadmin", "/backend", "/control", "/controlpanel",
	"/internal", "/private", "/staff", "/superadmin", "/moderator",
}

var artifactPaths = []string{
	"/.git/HEAD", "/.git/config", "/.git/index", "/.git/logs/HEAD",
	"/.svn/entries", "/.svn/wc.db", "/.hg/requires", "/.bzr/branch-format",
	"/.env", "/.env.local", "/.env.production", "/.env.development", "/.env.dev",
	"/.env.staging", "/.env.backup", "/.env.save", "/env.js", "/config.env",
	"/package.json", "/package-lock.json", "/yarn.lock", "/composer.json",
	"/pnpm-lock.yaml", "/bun.lockb", "/composer.lock", "/Gemfile", "/Gemfile.lock",
	"/requirements.txt", "/go.mod", "/go.sum", "/Cargo.toml", "/Cargo.lock",
	"/pom.xml", "/build.gradle", "/gradle.properties",
	"/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml", "/.dockerignore",
	"/.gitlab-ci.yml", "/.github/workflows/ci.yml", "/.travis.yml", "/.circleci/config.yml",
	"/Jenkinsfile", "/web.config", "/.idea/workspace.xml", "/.vscode/settings.json",
	"/id_rsa", "/id_dsa", "/id_ed25519", "/.ssh/id_rsa", "/.aws/credentials",
	"/.npmrc", "/.dockercfg", "/.docker/config.json", "/.netrc", "/.htpasswd",
	"/.htaccess", "/.git-credentials", "/credentials.json", "/secrets.json",
	"/.gitignore", "/.gitattributes", "/.editorconfig", "/tsconfig.json",
	"/next.config.js", "/nuxt.config.js", "/vite.config.js",
}

var frameworkPaths = []string{
	"/wp-login.php", "/wp-admin/", "/wp-config.php", "/wp-config.php.bak",
	"/wp-json/wp/v2/users", "/xmlrpc.php", "/wp-content/debug.log",
	"/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
	"/storage/logs/laravel.log", "/.env.example", "/artisan",
	"/admin/login/?next=/", "/static/admin/", "/django-admin/",
	"/rails/info/properties", "/rails/info/routes", "/phpinfo.php", "/info.php",
	"/node_modules/", "/bower.json", "/gulpfile.js", "/webpack.config.js",
	"/trace.axd", "/elmah.axd", "/server-status", "/server-info",
	"/.well-known/acme-challenge/", "/cgi-bin/", "/cgi-bin/test.cgi",
}

var apiPaths = []string{
	"/api", "/api/", "/api/v1", "/api/v2", "/api/v3", "/api/docs", "/api/swagger",
	"/swagger", "/swagger-ui.html", "/swagger/index.html", "/swagger.json",
	"/swagger-ui/", "/redoc", "/docs", "/openapi.json", "/openapi.yaml",
	"/api/openapi.json", "/api/swagger.json", "/v2/api-docs", "/v3/api-docs",
	"/api-docs", "/graphql", "/graphiql", "/playground", "/altair",
	"/api/health", "/api/health/live", "/api/health/ready", "/api/status",
	"/api/ping", "/api/version", "/api/config", "/api/schema",
	"/api/users", "/api/admin", "/api/internal", "/api/debug", "/api/test",
	"/rest", "/rest/v1", "/soap", "/wsdl", "/services", "/jsonrpc", "/rpc",
}

var configPaths = []string{
	"/config.json", "/config.js", "/config.yml", "/config.yaml", "/config.xml",
	"/config.php", "/settings.json", "/settings.py", "/appsettings.json",
	"/appsettings.Production.json", "/local.settings.json", "/.env.prod", "/.env.test", "/.envrc",
	"/application.properties", "/application.yml", "/application.yaml",
	"/application-prod.properties", "/application-prod.yml",
	"/config/database.yml", "/config/secrets.yml", "/config.inc.php",
	"/configuration.php", "/conf/server.xml", "/WEB-INF/web.xml",
	"/META-INF/MANIFEST.MF", "/phpmyadmin/", "/pma/", "/adminer.php",
	"/.well-known/", "/debug", "/debug/pprof/", "/debug/pprof/goroutine",
	"/debug/vars", "/metrics", "/prometheus",
}

var actuatorPaths = []string{
	"/actuator", "/actuator/health", "/actuator/env", "/actuator/configprops",
	"/actuator/heapdump", "/actuator/threaddump", "/actuator/mappings",
	"/actuator/beans", "/actuator/loggers", "/actuator/metrics", "/actuator/info",
	"/actuator/httptrace", "/actuator/auditevents", "/actuator/scheduledtasks",
	"/manage/health", "/manage/env", "/env", "/health", "/metrics", "/info",
}

// techSpecificPaths returns extra paths likely to exist given the detected
// stack. Matching is case-insensitive on the fingerprint hints.
func techSpecificPaths(hints []string) []string {
	joined := strings.ToLower(strings.Join(hints, " "))
	var out []string
	addIf := func(needle string, paths ...string) {
		if needle == "" || strings.Contains(joined, needle) {
			out = append(out, paths...)
		}
	}

	addIf("php",
		"/info.php", "/phpinfo.php", "/test.php", "/shell.php", "/php.ini",
		"/.user.ini", "/config.php.swp", "/index.php~",
	)
	addIf("laravel",
		"/telescope", "/telescope/requests", "/horizon", "/horizon/api/stats",
		"/_ignition/health-check", "/_ignition/execute-solution",
		"/storage/logs/laravel.log", "/.env",
	)
	addIf("wordpress",
		"/wp-json/wp/v2/users", "/wp-content/uploads/", "/wp-content/plugins/",
		"/wp-content/themes/", "/?author=1", "/wp-cron.php",
	)
	addIf("symfony",
		"/_profiler", "/_profiler/phpinfo", "/app_dev.php", "/config.php",
		"/_fragment", "/app/config/parameters.yml",
	)
	addIf("django",
		"/admin/", "/static/admin/", "/__debug__/", "/api-auth/login/",
		"/media/", "/db.sqlite3",
	)
	addIf("rails",
		"/rails/info/routes", "/rails/info/properties", "/rails/mailers",
		"/sidekiq", "/config/database.yml", "/assets/manifest.json",
	)
	addIf("spring",
		"/actuator", "/actuator/env", "/actuator/heapdump", "/v3/api-docs",
		"/swagger-ui.html", "/h2-console", "/jolokia", "/jolokia/list",
	)
	addIf("node",
		"/package.json", "/.npmrc", "/server.js", "/app.js", "/yarn.lock",
		"/.env", "/debug",
	)
	addIf("express",
		"/package.json", "/api/", "/users", "/status", "/__express",
	)
	addIf("next",
		"/_next/static/", "/_next/data/", "/next.config.js", "/api/", "/.env.local",
	)
	addIf("nuxt",
		"/_nuxt/", "/__nuxt_error", "/nuxt.config.js", "/api/", "/.env",
	)
	addIf("fastapi",
		"/docs", "/redoc", "/openapi.json", "/api/docs", "/health",
	)
	addIf("flask",
		"/console", "/debug", "/static/", "/instance/config.py", "/.env",
	)
	addIf("gin",
		"/swagger/index.html", "/swagger/doc.json", "/debug/pprof/", "/metrics",
	)
	addIf("asp.net",
		"/trace.axd", "/elmah.axd", "/web.config", "/web.config.bak",
		"/Global.asax", "/App_Data/", "/bin/", "/glimpse.axd",
	)
	addIf("tomcat",
		"/manager/html", "/manager/status", "/host-manager/html",
		"/examples/servlets/", "/docs/", "/WEB-INF/web.xml",
	)
	addIf("nginx",
		"/nginx_status", "/status", "/.well-known/",
	)
	addIf("apache",
		"/server-status", "/server-info", "/.htaccess", "/.htpasswd",
	)
	addIf("drupal",
		"/CHANGELOG.txt", "/user/login", "/admin", "/sites/default/settings.php",
		"/core/install.php", "/node/1",
	)
	addIf("joomla",
		"/administrator/", "/configuration.php", "/configuration.php.bak",
		"/README.txt", "/htaccess.txt",
	)
	return out
}

func joinURL(base, path string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base + path
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	return u.String()
}
