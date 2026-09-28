package crawler

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

type browserDependencyAdmitter interface {
	AdmitBrowserResourceDomains([]string) []string
}

var passiveDependencyURLRes = []*regexp.Regexp{
	regexp.MustCompile(`(?is)<(?:script|img|source|audio|video)\b[^>]*\bsrc\s*=\s*["']([^"']+)["']`),
	regexp.MustCompile(`(?is)<link\b[^>]*\bhref\s*=\s*["']([^"']+)["']`),
}

// passiveDependencyHosts learns exact hosts only from resource references in a
// successful in-scope document. Anchor/form destinations are deliberately not
// admitted; the browser request guard independently restricts this list to
// credential-stripped passive resource types.
func passiveDependencyHosts(pageURL, body string, headers map[string]string) []string {
	base, err := url.Parse(pageURL)
	if err != nil || base.Hostname() == "" {
		return nil
	}
	seen := make(map[string]struct{})
	add := func(raw string) {
		candidate, err := base.Parse(strings.TrimSpace(raw))
		if err != nil || candidate.User != nil || (candidate.Scheme != "http" && candidate.Scheme != "https") {
			return
		}
		host := strings.ToLower(candidate.Hostname())
		if host != "" && !strings.EqualFold(host, base.Hostname()) {
			seen[host] = struct{}{}
		}
	}
	for _, pattern := range passiveDependencyURLRes {
		for _, match := range pattern.FindAllStringSubmatch(body, -1) {
			if len(match) == 2 {
				add(match[1])
			}
		}
	}
	for name, value := range headers {
		if !strings.EqualFold(name, "Content-Security-Policy") {
			continue
		}
		for _, token := range strings.Fields(value) {
			token = strings.Trim(token, ";,\"'")
			if strings.HasPrefix(token, "http://") || strings.HasPrefix(token, "https://") {
				add(token)
			}
		}
	}
	hosts := make([]string, 0, len(seen))
	for host := range seen {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	if len(hosts) > 32 {
		hosts = hosts[:32]
	}
	return hosts
}

func (c *Crawler) adoptPassiveBrowserDependencies(pageURL, body string, headers map[string]string) {
	admitter, ok := c.client.(browserDependencyAdmitter)
	if !ok {
		return
	}
	added := admitter.AdmitBrowserResourceDomains(passiveDependencyHosts(pageURL, body, headers))
	if len(added) == 0 {
		return
	}
	_ = c.emit("browser_dependencies_adopted", "Passive browser dependencies learned from the in-scope document", map[string]interface{}{
		"phase": "crawling", "document_host": hostOnly(pageURL), "dependency_hosts": added,
		"credential_policy": "stripped", "request_types": []string{"script", "stylesheet", "image", "font", "media"},
	})
}

func hostOnly(raw string) string {
	parsed, _ := url.Parse(raw)
	return strings.ToLower(parsed.Hostname())
}
