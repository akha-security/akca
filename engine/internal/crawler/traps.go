package crawler

import (
	"net/url"
	"regexp"
	"strings"
)

var trapPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)/calendar/\d{4}/\d{2}`),
	regexp.MustCompile(`(?i)(page|p|offset|start)=\d{3,}`),
	regexp.MustCompile(`(?i)(filter|facet|sort|orderby|category|brand|color|size)=`),
	regexp.MustCompile(`(?i)/users?/:\w+/\d{5,}`),
	regexp.MustCompile(`(?i)(sessionid|sid|phpsessid)=`),
}

// IsCrawlerTrap detects calendars, faceted navigation, infinite query permutations, and repeated dynamic routes.
func IsCrawlerTrap(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return true
	}
	pathQuery := u.Path + "?" + u.RawQuery
	for _, re := range trapPatterns {
		if re.MatchString(pathQuery) {
			return true
		}
	}
	params := u.Query()
	if len(params) > 8 {
		return true
	}
	seen := map[string]int{}
	for k, vals := range params {
		key := strings.ToLower(k)
		seen[key]++
		for _, v := range vals {
			if len(v) > 128 {
				return true
			}
		}
	}
	return false
}
