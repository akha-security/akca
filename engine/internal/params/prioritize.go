package params

import (
	"net/http"
	"sort"
	"strings"
)

// PrioritizedWordlist returns parameter names with endpoint-relevant names first.
func PrioritizedWordlist(endpointURL string) []string {
	base := Wordlist()
	lower := strings.ToLower(endpointURL)
	var front, rest []string
	seen := map[string]struct{}{}
	addFront := func(names ...string) {
		for _, n := range names {
			if _, ok := seen[n]; ok {
				continue
			}
			seen[n] = struct{}{}
			front = append(front, n)
		}
	}
	addFront("id", "q", "debug", "test", "file", "url", "redirect", "token", "search", "page")
	switch {
	case strings.Contains(lower, "checkout"), strings.Contains(lower, "cart"), strings.Contains(lower, "payment"):
		addFront("amount", "price", "total", "quantity", "coupon", "discount", "currency", "order_id")
	case strings.Contains(lower, "login"), strings.Contains(lower, "auth"), strings.Contains(lower, "oauth"):
		addFront("username", "password", "email", "token", "redirect_uri", "client_id", "state", "code", "admin", "role")
	case strings.Contains(lower, "admin"), strings.Contains(lower, "manage"), strings.Contains(lower, "dashboard"):
		addFront("admin", "is_admin", "role", "roles", "sudo", "impersonate", "bypass", "debug", "dev_mode", "user_id")
	case strings.Contains(lower, "proxy"), strings.Contains(lower, "fetch"), strings.Contains(lower, "view"), strings.Contains(lower, "render"):
		addFront("url", "dest", "destination", "target", "proxy", "feed", "remote", "load_url", "redirect", "site")
	case strings.Contains(lower, "cloud"), strings.Contains(lower, "s3"), strings.Contains(lower, "bucket"), strings.Contains(lower, "storage"):
		addFront("bucket", "s3_bucket", "s3_key", "region", "account_id", "role_arn")
	case strings.Contains(lower, "upload"), strings.Contains(lower, "file"):
		addFront("file", "filename", "filepath", "path", "upload", "name", "type", "template_path")
	case strings.Contains(lower, "search"), strings.Contains(lower, "query"):
		addFront("q", "query", "search", "term", "keyword", "filter", "sort")
	case strings.Contains(lower, "graphql"):
		addFront("query", "variables", "operationName")
	case strings.Contains(lower, "api"), strings.Contains(lower, "rest"):
		addFront("id", "user_id", "token", "limit", "offset", "page")
	}
	for _, n := range base {
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		rest = append(rest, n)
	}
	out := make([]string, 0, len(front)+len(rest))
	out = append(out, front...)
	out = append(out, rest...)
	return out
}

// DifferentialWordlist returns a compact probe list for active hidden-parameter discovery.
// The full Wordlist() remains available for passive extraction elsewhere.
func DifferentialWordlist(endpointURL string, maxItems int) []string {
	full := PrioritizedWordlist(endpointURL)
	if maxItems <= 0 || len(full) <= maxItems {
		return full
	}
	return full[:maxItems]
}

// DifferentialCandidates merges endpoint-local passive hints and a small set
// of already proven names with the built-in list, then applies the cap to the
// final list. Applying the cap last is important: the former implementation
// prepended every learned name after truncation and silently bypassed it.
func DifferentialCandidates(endpointURL string, hints []DiscoveredParameter, learned []string, known map[string]struct{}, maxItems int) []string {
	orderedHints := append([]DiscoveredParameter(nil), hints...)
	sort.SliceStable(orderedHints, func(i, j int) bool { return orderedHints[i].Priority > orderedHints[j].Priority })
	seen := make(map[string]struct{}, len(known)+len(orderedHints)+len(learned))
	for name := range known {
		seen[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
	}
	capacity := maxItems
	if capacity < 0 {
		capacity = 0
	}
	out := make([]string, 0, capacity)
	add := func(name string) bool {
		name = strings.TrimSpace(name)
		key := strings.ToLower(name)
		if !validCandidateName(name) {
			return true
		}
		if _, exists := seen[key]; exists {
			return true
		}
		seen[key] = struct{}{}
		out = append(out, name)
		return maxItems <= 0 || len(out) < maxItems
	}
	base := PrioritizedWordlist(endpointURL)
	coreCount := 32
	if maxItems > 0 && coreCount > maxItems {
		coreCount = maxItems
	}
	if coreCount > len(base) {
		coreCount = len(base)
	}
	for _, name := range base[:coreCount] {
		if !add(name) {
			return out
		}
	}
	hintLimit := len(orderedHints)
	if maxItems > 0 && hintLimit > maxItems/2 {
		hintLimit = maxItems / 2
	}
	for _, hint := range orderedHints[:hintLimit] {
		if !add(hint.Name) {
			return out
		}
	}
	for _, name := range learned {
		if !add(name) {
			return out
		}
	}
	for _, name := range base[coreCount:] {
		if !add(name) {
			return out
		}
	}
	return out
}

func primaryProbeMethod(method string) string {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return strings.ToUpper(method)
	default:
		return http.MethodGet
	}
}
