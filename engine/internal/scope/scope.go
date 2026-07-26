package scope

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/config"
)

type Engine struct {
	includeDomains []string
	excludeDomains []string
	excludedPaths  []string
}

func NewEngine(cfg config.ScanConfig) *Engine {
	return &Engine{
		includeDomains: normalizeList(cfg.IncludeDomains),
		excludeDomains: normalizeList(cfg.ExcludeDomains),
		excludedPaths:  cfg.ExcludedPaths,
	}
}

func normalizeList(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if d := config.NormalizeDomain(item); d != "" {
			out = append(out, d)
		}
	}
	return out
}

func (e *Engine) IsInScope(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if e.isExcludedHost(host) {
		return false
	}
	if len(e.includeDomains) == 0 {
		return !e.isPathExcluded(u.Path)
	}
	if !e.matchesInclude(host) {
		return false
	}
	return !e.isPathExcluded(u.Path)
}

func (e *Engine) CanActivelyTest(rawURL string) bool {
	return e.IsInScope(rawURL)
}

func (e *Engine) Explain(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "invalid url"
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "unsupported scheme"
	}
	host := strings.ToLower(u.Hostname())
	if e.isExcludedHost(host) {
		return fmt.Sprintf("host %q is excluded", host)
	}
	if len(e.includeDomains) > 0 && !e.matchesInclude(host) {
		return fmt.Sprintf("host %q not in include domains", host)
	}
	if e.isPathExcluded(u.Path) {
		return fmt.Sprintf("path %q is excluded", u.Path)
	}
	return "in scope"
}

func (e *Engine) isExcludedHost(host string) bool {
	for _, ex := range e.excludeDomains {
		if hostMatches(host, ex) {
			return true
		}
	}
	return false
}

func (e *Engine) matchesInclude(host string) bool {
	for _, inc := range e.includeDomains {
		if hostMatches(host, inc) {
			return true
		}
	}
	return false
}

func hostMatches(host, rule string) bool {
	rule = config.NormalizeDomain(rule)
	host = config.NormalizeDomain(host)
	if host == rule {
		return true
	}
	if strings.HasPrefix(rule, "*.") {
		base := strings.TrimPrefix(rule, "*.")
		return host == base || strings.HasSuffix(host, "."+base)
	}
	return false
}

func (e *Engine) isPathExcluded(path string) bool {
	for _, p := range e.excludedPaths {
		if p == "" {
			continue
		}
		if strings.HasSuffix(p, "*") {
			prefix := strings.TrimSuffix(p, "*")
			if strings.HasPrefix(path, prefix) {
				return true
			}
			continue
		}
		if path == p {
			return true
		}
	}
	return false
}
