package scope

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"

	"github.com/akha-security/akca/engine/internal/config"
	"golang.org/x/net/publicsuffix"
)

type Engine struct {
	mu              sync.RWMutex
	includeDomains  []string
	excludeDomains  []string
	excludedPaths   []string
	adoptedHosts    map[string]struct{}
	allowLinkedAPIs bool
}

func NewEngine(cfg config.ScanConfig) *Engine {
	return &Engine{
		includeDomains:  normalizeList(cfg.IncludeDomains),
		excludeDomains:  normalizeList(cfg.ExcludeDomains),
		excludedPaths:   cfg.ExcludedPaths,
		adoptedHosts:    make(map[string]struct{}),
		allowLinkedAPIs: cfg.IncludeLinkedAPISubdomains,
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

// AdoptHost adds an off-host redirect target or verified linked API host to the active in-scope set.
func (e *Engine) AdoptHost(host string) {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.adoptedHosts == nil {
		e.adoptedHosts = make(map[string]struct{})
	}
	e.adoptedHosts[host] = struct{}{}
}

func (e *Engine) isAdoptedHost(host string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.adoptedHosts == nil {
		return false
	}
	_, ok := e.adoptedHosts[host]
	return ok
}

func (e *Engine) IsInScope(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	host := strings.ToLower(u.Host)
	// Strip default scheme ports for canonical matching
	if (u.Scheme == "http" && strings.HasSuffix(host, ":80")) ||
		(u.Scheme == "https" && strings.HasSuffix(host, ":443")) {
		host = strings.ToLower(u.Hostname())
	}
	if e.isExcludedHost(host) {
		return false
	}
	if len(e.includeDomains) == 0 {
		return !e.isPathExcluded(u.Path)
	}
	if e.isAdoptedHost(host) {
		return !e.isPathExcluded(u.Path)
	}
	if e.matchesInclude(host) {
		return !e.isPathExcluded(u.Path)
	}
	if e.allowLinkedAPIs && e.matchesLinkedAPI(host) {
		return !e.isPathExcluded(u.Path)
	}
	return false
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
	host := strings.ToLower(u.Host)
	if (u.Scheme == "http" && strings.HasSuffix(host, ":80")) ||
		(u.Scheme == "https" && strings.HasSuffix(host, ":443")) {
		host = strings.ToLower(u.Hostname())
	}
	if e.isExcludedHost(host) {
		return fmt.Sprintf("host %q is excluded", host)
	}
	if e.isPathExcluded(u.Path) {
		return fmt.Sprintf("path %q is excluded", u.Path)
	}
	if len(e.includeDomains) > 0 && !e.matchesInclude(host) && !e.isAdoptedHost(host) && (!e.allowLinkedAPIs || !e.matchesLinkedAPI(host)) {
		return fmt.Sprintf("host %q not in include domains or linked APIs", host)
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

func (e *Engine) matchesLinkedAPI(host string) bool {
	if isLocalOrIP(host) {
		return false
	}
	for _, inc := range e.includeDomains {
		if isLocalOrIP(inc) || strings.Contains(inc, ":") {
			continue
		}
		if SameRootDomain(host, inc) && IsLinkedAPISubdomain(host, inc) {
			return true
		}
	}
	return false
}

func isLocalOrIP(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if split, _, err := net.SplitHostPort(h); err == nil {
		h = split
	}
	h = strings.Trim(h, "[]")
	if h == "localhost" || h == "127.0.0.1" || h == "::1" {
		return true
	}
	return net.ParseIP(h) != nil
}

func hostMatches(host, rule string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	rule = strings.ToLower(strings.TrimSpace(rule))
	if host == rule {
		return true
	}
	// If rule specifies a port (e.g. "localhost:8088"), exact host:port match is enforced
	if strings.Contains(rule, ":") && !strings.HasPrefix(rule, "*.") {
		return host == rule
	}
	// Extract hostname without port for domain matching
	hostHostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostHostname = h
	}
	ruleHostname := rule
	if h, _, err := net.SplitHostPort(rule); err == nil {
		ruleHostname = h
	}
	if hostHostname == ruleHostname {
		return true
	}
	if strings.HasPrefix(ruleHostname, "*.") {
		base := strings.TrimPrefix(ruleHostname, "*.")
		return hostHostname == base || strings.HasSuffix(hostHostname, "."+base)
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

// RootDomain extracts the base registrable domain (eTLD+1), using Public Suffix List.
func RootDomain(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if ip := net.ParseIP(host); ip != nil {
		return host
	}
	if strings.HasPrefix(host, "www.") {
		host = strings.TrimPrefix(host, "www.")
	}
	etld1, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err == nil && etld1 != "" {
		return etld1
	}
	// Fallback for custom local domain structures (e.g. intranet.local)
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// SameRootDomain reports whether two hostnames belong to the same registrable domain.
func SameRootDomain(host1, host2 string) bool {
	r1 := RootDomain(host1)
	r2 := RootDomain(host2)
	return r1 != "" && r1 == r2
}

// IsLinkedAPISubdomain checks if a host is an authorized API or service subdomain of the target root domain.
func IsLinkedAPISubdomain(host, baseHost string) bool {
	if host == "" || baseHost == "" {
		return false
	}
	if !SameRootDomain(host, baseHost) {
		return false
	}
	h := strings.ToLower(host)
	if splitHost, _, err := net.SplitHostPort(h); err == nil {
		h = splitHost
	}
	base := strings.ToLower(baseHost)
	if splitBase, _, err := net.SplitHostPort(base); err == nil {
		base = splitBase
	}
	if h == base {
		return true
	}
	// Common API / service prefixes strictly required
	for _, pfx := range []string{
		"api.", "api-", "auth.", "backend.", "graphql.", "gateway.", "services.",
		"app.", "v1.", "v2.", "v3.", "rest.", "ws.", "admin.", "stage.", "dev.",
	} {
		if strings.HasPrefix(h, pfx) || strings.Contains(h, "."+pfx) {
			return true
		}
	}
	return false
}
