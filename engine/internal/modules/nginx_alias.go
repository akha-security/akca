package modules

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

var nginxAliasSuffixes = []string{
	"static", "assets", "uploads", "images", "img", "css", "js",
	"fonts", "media", "files", "content", "resources", "public",
	"dist", "build", "lib", "vendor", "node_modules",
	"app", "application", "src", "source", "web", "www", "htdocs",
	"html", "templates", "views", "pages", "layouts", "components",
	"admin", "administrator", "panel", "dashboard", "config",
	"configuration", "settings", "setup", "install",
	"api", "api-docs", "swagger", "graphql", "rest", "v1", "v2", "v3",
	"data", "database", "db", "backup", "backups", "dump", "export",
	"logs", "log", "tmp", "temp", "cache", "storage",
	"docs", "doc", "documentation",
	"wp-content", "wp-includes", "wp-admin",
	".env", ".git", "server-status",
}

func (r *Runner) runNginxAlias(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("nginx_alias", target); !ok {
		r.emitSkip("nginx_alias", target, reason)
		return nil
	}

	u, err := url.Parse(target.EndpointURL)
	if err != nil || u.Path == "" || u.Path == "/" {
		return nil
	}

	segment := firstNginxPathSegment(u.Path)
	if segment == "" {
		return nil
	}

	origin := u.Scheme + "://" + u.Host

	// Check if the host is a wildcard SPA / catch-all host (returns 200 for any random path)
	wildcardURL := origin + "/" + segment + "-akca-nonexistent-path-check-" + randomProbeToken()
	wildcardRR, err := r.client.Do(ctx, "GET", wildcardURL, nil, nil)
	if err == nil && wildcardRR.Response.StatusCode == 200 && len(wildcardRR.Response.Body) > 100 {
		// Server returns 200 for nonexistent paths under this prefix (SPA/catch-all); skip to avoid false positives
		return nil
	}

	baseline, baselineErr := r.cachedEmptyProbe(ctx, target)
	if baselineErr != nil {
		return nil
	}

	var out []ModuleFinding
	injections := []string{"..", "..;", "..%3B"}

	for _, inj := range injections {
		if ctx.Err() != nil {
			break
		}
		for _, suffix := range nginxAliasSuffixes {
			if ctx.Err() != nil {
				break
			}
			traversalPath := "/" + segment + inj + "/" + suffix
			probeURL := origin + traversalPath
			if !r.scope.IsInScope(probeURL) {
				continue
			}

			rr, err := r.client.Do(ctx, "GET", probeURL, nil, nil)
			if err != nil || rr.Response.StatusCode != 200 || len(rr.Response.Body) < 50 {
				continue
			}

			// Reject binary/static asset content types
			ct := strings.ToLower(rr.Response.Headers["Content-Type"])
			if isStaticAssetContentType(ct) {
				continue
			}

			body := rr.Response.Body

			// Differential Control 1: Must NOT match the in-alias path /{segment}/{suffix}
			inAliasURL := origin + "/" + segment + "/" + suffix
			inAliasRR, inErr := r.client.Do(ctx, "GET", inAliasURL, nil, nil)
			if inErr == nil && inAliasRR.Response.StatusCode == 200 && bodiesSimilar(body, inAliasRR.Response.Body) {
				// Server routes /{segment}{inj}/{suffix} identically to in-alias path (prefix routing/SPA)
				return nil
			}

			// Differential Control 2: Must NOT match a random nonexistent suffix under the same traversal prefix
			canaryURL := origin + "/" + segment + inj + "/akca-canary-" + randomProbeToken()
			canaryRR, canErr := r.client.Do(ctx, "GET", canaryURL, nil, nil)
			if canErr == nil && canaryRR.Response.StatusCode == 200 && bodiesSimilar(body, canaryRR.Response.Body) {
				// Server is suffix-invariant under /{segment}{inj}/ (a catch-all); skip
				continue
			}

			// Differential Control 3: Must NOT match /{suffix} already reachable at the web root
			rootURL := origin + "/" + suffix
			rootRR, rootErr := r.client.Do(ctx, "GET", rootURL, nil, nil)
			if rootErr == nil && rootRR.Response.StatusCode == 200 && bodiesSimilar(body, rootRR.Response.Body) {
				// Plain unescaped path already serves this body without traversal; skip
				continue
			}

			// Stability confirmation: re-fetch once more to guarantee reproducibility
			reRR, reErr := r.client.Do(ctx, "GET", probeURL, nil, nil)
			if reErr != nil || reRR.Response.StatusCode != 200 || !bodiesSimilar(body, reRR.Response.Body) {
				continue
			}

			signal := "alias_traversal"
			p := defaultPayload("nginx_alias", signal, traversalPath, signal)
			f := r.verifyAndBuild(ctx, "nginx_alias", target, p, baseline, rr, signal, false, false, "", "")
			if f != nil {
				f.Severity = "high"
				f.Title = fmt.Sprintf("Nginx Off-By-Slash Alias Directory Traversal (/%s%s/%s)", segment, inj, suffix)
				f.Description = fmt.Sprintf("Nginx alias misconfiguration (missing trailing slash in location directive) allows directory traversal outside the configured alias directory via '%s'.", traversalPath)
				r.recordFinding(ctx, &out, f, "nginx_alias", signal)
				return out
			}
		}
	}

	return out
}

func firstNginxPathSegment(urlPath string) string {
	parts := strings.Split(strings.TrimPrefix(urlPath, "/"), "/")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" && !strings.Contains(p, ".") {
			return p
		}
	}
	return ""
}

func isStaticAssetContentType(ct string) bool {
	return strings.HasPrefix(ct, "image/") ||
		strings.HasPrefix(ct, "font/") ||
		strings.HasPrefix(ct, "audio/") ||
		strings.HasPrefix(ct, "video/") ||
		strings.Contains(ct, "octet-stream")
}

func bodiesSimilar(a, b string) bool {
	if a == b {
		return true
	}
	la, lb := len(a), len(b)
	if la == 0 || lb == 0 {
		return false
	}
	diff := la - lb
	if diff < 0 {
		diff = -diff
	}
	maxLen := la
	if lb > maxLen {
		maxLen = lb
	}
	return float64(diff)/float64(maxLen) < 0.08
}
