package params

import (
	"net/http"
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
		addFront("username", "password", "email", "token", "redirect_uri", "client_id", "state", "code")
	case strings.Contains(lower, "upload"), strings.Contains(lower, "file"):
		addFront("file", "filename", "path", "upload", "name", "type")
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

func primaryProbeMethod(method string) string {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return strings.ToUpper(method)
	default:
		return http.MethodGet
	}
}
