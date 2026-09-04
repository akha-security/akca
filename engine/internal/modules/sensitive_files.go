package modules

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

type sensitiveFileDef struct {
	path        string
	kind        string
	title       string
	severity    string
	fingerprint string
	desc        string
}

var sensitiveFileDefs = []sensitiveFileDef{
	// Leftover web installers. These use a semantic multi-signal matcher below;
	// a generic page containing the word "install" is intentionally insufficient.
	{path: "/install.php", kind: "exposed_installer", title: "Application Installer Exposed", severity: "high", desc: "An interactive application installer is publicly reachable and may permit reconfiguration or takeover."},
	{path: "/installer.php", kind: "exposed_installer", title: "Application Installer Exposed", severity: "high", desc: "An interactive application installer is publicly reachable and may permit reconfiguration or takeover."},
	{path: "/setup.php", kind: "exposed_installer", title: "Application Setup Wizard Exposed", severity: "high", desc: "An interactive setup wizard is publicly reachable and may permit reconfiguration or takeover."},
	{path: "/install/", kind: "exposed_installer", title: "Application Installer Exposed", severity: "high", desc: "An interactive application installer is publicly reachable and may permit reconfiguration or takeover."},
	{path: "/setup/", kind: "exposed_installer", title: "Application Setup Wizard Exposed", severity: "high", desc: "An interactive setup wizard is publicly reachable and may permit reconfiguration or takeover."},
	{path: "/installation/index.php", kind: "exposed_installer", title: "Application Installer Exposed", severity: "high", desc: "An interactive application installer is publicly reachable and may permit reconfiguration or takeover."},
	// Secrets, Environment & Cloud Credentials
	{
		path:        "/.env",
		kind:        "env_file_leak",
		title:       "Environment Configuration (.env) File Disclosed",
		severity:    "critical",
		fingerprint: `APP_KEY=`,
		desc:        "Environment configuration file was accessed, leaking API keys, database credentials, and application secrets.",
	},
	{
		path:        "/.git/HEAD",
		kind:        "git_head_leak",
		title:       "Git Source Control Repository (.git/HEAD) Disclosed",
		severity:    "high",
		fingerprint: `ref: refs/`,
		desc:        "Git source control repository directory is exposed, allowing reconstruction of application source code.",
	},
	{
		path:        "/.dockerenv",
		kind:        "dockerenv_leak",
		title:       "Docker Container Environment Indicator Disclosed",
		severity:    "low",
		fingerprint: ``,
		desc:        "Docker container indicator file was discovered on the server.",
	},
	{
		path:        "/docker-compose.yml",
		kind:        "docker_compose_leak",
		title:       "Docker Compose Infrastructure File Disclosed",
		severity:    "high",
		fingerprint: `version:`,
		desc:        "Docker Compose orchestration configuration file is publicly accessible, revealing backend service topology and passwords.",
	},
	// Package Managers & Dependencies
	{
		path:        "/composer.json",
		kind:        "composer_json_leak",
		title:       "PHP Composer Configuration File Disclosed",
		severity:    "medium",
		fingerprint: `"require":`,
		desc:        "PHP composer.json file is publicly accessible, leaking backend package dependencies and internal namespace mappings.",
	},
	{
		path:        "/composer.lock",
		kind:        "composer_lock_leak",
		title:       "PHP Composer Lock File Disclosed",
		severity:    "medium",
		fingerprint: `"packages":`,
		desc:        "PHP composer.lock file is accessible, exposing exact dependency versions.",
	},
	{
		path:        "/package.json",
		kind:        "package_json_leak",
		title:       "Node.js package.json File Disclosed",
		severity:    "medium",
		fingerprint: `"dependencies":`,
		desc:        "Node.js package.json is publicly accessible, disclosing server dependencies and private build scripts.",
	},
	// Web Servers & Infra Configs
	{
		path:        "/web.config",
		kind:        "web_config_leak",
		title:       "IIS web.config Configuration File Disclosed",
		severity:    "high",
		fingerprint: `<configuration>`,
		desc:        "Microsoft IIS web.config file was downloaded, exposing connection strings, handlers, and security rules.",
	},
	{
		path:        "/Dockerfile",
		kind:        "dockerfile_leak",
		title:       "Container Dockerfile Disclosed",
		severity:    "medium",
		fingerprint: `FROM `,
		desc:        "Container build Dockerfile is accessible, leaking base image versions and internal environment variables.",
	},
	{
		path:        "/.htpasswd",
		kind:        "htpasswd_leak",
		title:       "Apache .htpasswd Password Hash File Disclosed",
		severity:    "critical",
		fingerprint: `:`,
		desc:        "Apache .htpasswd file containing HTTP Basic authentication user password hashes was accessed.",
	},
	{
		path:        "/.npmrc",
		kind:        "npmrc_leak",
		title:       "NPM .npmrc Configuration / Auth Token Disclosed",
		severity:    "high",
		fingerprint: `_authToken`,
		desc:        ".npmrc file containing private NPM registry authentication tokens was accessed.",
	},
	{
		path:        "/phpinfo.php",
		kind:        "phpinfo_leak",
		title:       "PHP phpinfo() Diagnostic Page Exposed",
		severity:    "medium",
		fingerprint: `PHP Version `,
		desc:        "PHP diagnostic information page is publicly accessible, leaking PHP modules, environment variables, and filesystem paths.",
	},
	{
		path:        "/.DS_Store",
		kind:        "ds_store_leak",
		title:       "macOS .DS_Store Directory Index Disclosed",
		severity:    "low",
		fingerprint: `Bud1`,
		desc:        "Apple macOS .DS_Store file is accessible, allowing hidden file and folder enumeration.",
	},
	{
		path:        "/appsettings.json",
		kind:        "appsettings_leak",
		title:       "ASP.NET Core appsettings.json Configuration Disclosed",
		severity:    "high",
		fingerprint: `"ConnectionStrings":`,
		desc:        "ASP.NET Core configuration file is exposed, disclosing database connection strings and JWT signing keys.",
	},
	{
		path:        "/wp-config.php.bak",
		kind:        "wp_config_bak_leak",
		title:       "WordPress wp-config.php.bak Backup File Disclosed",
		severity:    "critical",
		fingerprint: `DB_PASSWORD`,
		desc:        "WordPress database credentials and authentication salts were disclosed in a backup file.",
	},
}

func (r *Runner) runSensitiveFiles(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("sensitive_file_discovery", target); !ok {
		r.emitSkip("sensitive_file_discovery", target, reason)
		return nil
	}
	if !r.endpointModuleOnce("sensitive_file_discovery", target) {
		return nil
	}

	u, err := url.Parse(target.EndpointURL)
	if err != nil {
		return nil
	}
	origin := u.Scheme + "://" + u.Host

	// Wildcard / SPA check
	wildcardURL := origin + "/akca-files-check-" + randomProbeToken()
	wRR, err := r.client.Do(ctx, "GET", wildcardURL, nil, nil)
	wildcard200 := (err == nil && wRR.Response.StatusCode == 200 && len(wRR.Response.Body) > 100)

	baseline, baselineErr := r.cachedEmptyProbe(ctx, target)
	if baselineErr != nil {
		return nil
	}

	var out []ModuleFinding
	for _, sf := range sensitiveFileDefs {
		if ctx.Err() != nil {
			break
		}
		// Smooth pacing delay between sensitive file requests to avoid WAF rate-limiting
		select {
		case <-ctx.Done():
			return out
		case <-time.After(80 * time.Millisecond):
		}

		probeURL := origin + sf.path
		if !r.scope.IsInScope(probeURL) {
			continue
		}

		rr, err := r.client.Do(ctx, "GET", probeURL, nil, nil)
		if err != nil || rr.Response.StatusCode != 200 {
			continue
		}

		body := rr.Response.Body
		if wildcard200 && bodiesSimilar(body, wRR.Response.Body) {
			continue
		}

		// Reject HTML 200 custom error pages (except for phpinfo which is HTML)
		if sf.kind != "phpinfo_leak" && sf.kind != "exposed_installer" && (strings.Contains(strings.ToLower(body), "<html") || strings.Contains(strings.ToLower(body), "<!doctype")) {
			continue
		}

		if sensitiveFileFingerprintMatches(sf, rr.Response) {
			signal := sf.kind
			p := defaultPayload("sensitive_file_discovery", signal, sf.path, signal)
			f := r.verifyAndBuild(ctx, "sensitive_file_discovery", target, p, baseline, rr, signal, false, false, "", "")
			if f != nil {
				f.Severity = sf.severity
				f.Title = sf.title
				f.Description = sf.desc
				r.recordFinding(ctx, &out, f, "sensitive_file_discovery", signal)
			}
		}
	}

	return out
}

func sensitiveFileFingerprintMatches(sf sensitiveFileDef, response httpclient.ResponseRecord) bool {
	body := response.Body
	if sf.kind == "exposed_installer" {
		return installerFingerprintMatches(response)
	}
	if sf.kind == "dockerenv_leak" {
		contentType := strings.ToLower(response.Headers["Content-Type"])
		trimmed := strings.TrimSpace(body)
		return len(body) <= 128 &&
			!strings.Contains(contentType, "html") &&
			!strings.Contains(contentType, "json") &&
			(trimmed == "" || strings.Contains(strings.ToLower(trimmed), "docker"))
	}
	return sf.fingerprint == "" || strings.Contains(body, sf.fingerprint)
}

func installerFingerprintMatches(response httpclient.ResponseRecord) bool {
	body := strings.ToLower(response.Body)
	if len(body) < 120 || len(body) > 4<<20 {
		return false
	}
	contentType := strings.ToLower(response.Headers["Content-Type"])
	if !strings.Contains(contentType, "html") && !strings.Contains(body, "<html") && !strings.Contains(body, "<form") {
		return false
	}
	identity := installerContainsAny(body, "installation wizard", "setup wizard", "web installer", "installation step", "installer - step", "install application")
	action := installerContainsAny(body, "database host", "database name", "system requirements", "configuration check", "license agreement", "start installation", "begin installation")
	interactive := strings.Contains(body, "<form") && installerContainsAny(body, "type=\"submit\"", "type='submit'", "<button")
	return identity && action && interactive
}

func installerContainsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func sensitiveFileSignalConfirmed(signal string, response httpclient.ResponseRecord) bool {
	if response.StatusCode != 200 {
		return false
	}
	for _, def := range sensitiveFileDefs {
		if def.kind == signal {
			return sensitiveFileFingerprintMatches(def, response)
		}
	}
	return false
}
