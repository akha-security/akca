package crawler

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

const (
	maxQueryLength        = 2048
	maxQueryParameters    = 16
	maxValuesPerQueryKey  = 3
	maxQueryValueLength   = 128
	maxRouteQueryVariants = 32
)

var trapPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)/calendar/\d{4}/\d{2}`),
	regexp.MustCompile(`(?i)(page|p|offset|start)=\d{3,}`),
	regexp.MustCompile(`(?i)/users?/:\w+/\d{5,}`),
	regexp.MustCompile(`(?i)(sessionid|sid|phpsessid)=`),
}

// routeQueryVariant separates route identity from query values so the crawler
// can recognize combinatorial growth over time without treating a parameter
// name (for example category) as a trap by itself.
func routeQueryVariant(rawURL, method string) (route, variant string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", ""
	}
	query := u.Query()
	if len(query) == 0 {
		return "", ""
	}
	keys := make([]string, 0, len(query))
	for key := range query {
		keys = append(keys, strings.ToLower(strings.TrimSuffix(key, "[]")))
	}
	sort.Strings(keys)
	u.RawQuery, u.Fragment = "", ""
	return strings.ToUpper(method) + " " + u.String() + "?" + strings.Join(keys, "&"), query.Encode()
}

var paginationParameters = map[string]struct{}{
	"cursor": {},
	"offset": {},
	"p":      {},
	"page":   {},
	"start":  {},
}

// IsCrawlerTrap detects structurally unbounded URLs. Ordinary business
// parameters such as category, filter and sort are intentionally accepted:
// their names alone are not evidence of combinatorial crawler growth.
func IsCrawlerTrap(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return true
	}
	// Apply a bound before parsing the query. Apart from being a strong trap
	// signal, an ever-growing query string can otherwise cause a large
	// allocation for every discovered URL.
	if len(u.RawQuery) > maxQueryLength {
		return true
	}
	pathQuery := u.Path + "?" + u.RawQuery
	for _, re := range trapPatterns {
		if re.MatchString(pathQuery) {
			return true
		}
	}
	params, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return true
	}
	if len(params) > 8 {
		return true
	}
	totalValues := 0
	seen := make(map[string]int, len(params))
	for k, vals := range params {
		key := strings.ToLower(strings.TrimSuffix(k, "[]"))
		seen[key] += len(vals)
		totalValues += len(vals)
		if _, pagination := paginationParameters[key]; pagination && seen[key] > 1 {
			return true
		}
		if seen[key] > maxValuesPerQueryKey {
			return true
		}
		for _, v := range vals {
			if len(v) > maxQueryValueLength {
				return true
			}
		}
	}
	if totalValues > maxQueryParameters {
		return true
	}
	return false
}
