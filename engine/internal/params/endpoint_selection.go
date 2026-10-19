package params

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
	"unicode"

	"github.com/akha-security/akca/engine/internal/storage"
)

type endpointSelectionStats struct {
	Inventory        int
	SkippedLowValue  int
	SkippedDuplicate int
	SkippedByLimit   int
}

// selectDiscoveryEndpoints keeps active guessing on request-shaped surfaces and
// collapses URL variants that differ only by parameter values or path IDs. The
// crawler may observe /page?id=1 and /page?id=2 as separate URLs, but probing the
// same hidden-name wordlist against both adds little coverage and multiplies the
// scan time.
func selectDiscoveryEndpoints(all []storage.DiscoveryEndpoint, limit int) ([]storage.DiscoveryEndpoint, endpointSelectionStats) {
	stats := endpointSelectionStats{Inventory: len(all)}
	selected := make([]storage.DiscoveryEndpoint, 0, len(all))
	seenFamilies := make(map[string]struct{}, len(all))

	for _, endpoint := range all {
		if !ShouldDiscoverEndpoint(endpoint.URL, endpoint.Method) || !likelyParameterEndpoint(endpoint) {
			stats.SkippedLowValue++
			continue
		}
		family := parameterEndpointFamily(endpoint)
		if _, exists := seenFamilies[family]; exists {
			stats.SkippedDuplicate++
			continue
		}
		seenFamilies[family] = struct{}{}
		if limit > 0 && len(selected) >= limit {
			stats.SkippedByLimit++
			continue
		}
		selected = append(selected, endpoint)
	}
	return selected, stats
}

func likelyParameterEndpoint(endpoint storage.DiscoveryEndpoint) bool {
	method := strings.ToUpper(strings.TrimSpace(endpoint.Method))
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	}
	if strings.TrimSpace(endpoint.RequestTemplate.Body) != "" {
		return true
	}
	u, err := url.Parse(endpoint.URL)
	if err != nil {
		return false
	}
	if u.RawQuery != "" || u.Path == "" || u.Path == "/" {
		return true
	}
	if responseLooksStructured(endpoint.RequestTemplate.ResponseHeaders) {
		return true
	}
	for _, segment := range strings.FieldsFunc(strings.ToLower(u.Path), func(r rune) bool {
		return r == '/' || r == '-' || r == '_'
	}) {
		switch segment {
		case "api", "graphql", "rest", "rpc", "search", "query", "filter",
			"login", "signin", "auth", "oauth", "callback", "admin", "account",
			"profile", "user", "users", "cart", "checkout", "payment", "upload",
			"import", "export", "report", "redirect", "proxy", "fetch":
			return true
		}
		if len(segment) >= 2 && segment[0] == 'v' && allDigits(segment[1:]) {
			return true
		}
	}
	return false
}

func responseLooksStructured(headers map[string]string) bool {
	for name, value := range headers {
		if strings.EqualFold(name, "Content-Type") {
			value = strings.ToLower(value)
			return strings.Contains(value, "json") || strings.Contains(value, "graphql") || strings.Contains(value, "xml")
		}
	}
	return false
}

func parameterEndpointFamily(endpoint storage.DiscoveryEndpoint) string {
	method := strings.ToUpper(strings.TrimSpace(endpoint.Method))
	if method == "" {
		method = http.MethodGet
	}
	u, err := url.Parse(endpoint.URL)
	if err != nil {
		return method + "|" + strings.ToLower(endpoint.URL)
	}
	queryNames := make([]string, 0, len(u.Query()))
	for name := range u.Query() {
		queryNames = append(queryNames, strings.ToLower(name))
	}
	sort.Strings(queryNames)

	bodyNames := ExtractFromTemplateBody(endpoint.URL, method, endpoint.RequestTemplate.ContentType, endpoint.RequestTemplate.Body)
	bodyShape := make([]string, 0, len(bodyNames))
	for _, parameter := range bodyNames {
		bodyShape = append(bodyShape, strings.ToLower(parameter.Name)+":"+string(parameter.Location))
	}
	sort.Strings(bodyShape)

	return strings.Join([]string{
		method,
		strings.ToLower(u.Scheme),
		strings.ToLower(u.Host),
		canonicalParameterPath(u.Path),
		strings.Join(queryNames, ","),
		strings.Join(bodyShape, ","),
	}, "|")
}

func canonicalParameterPath(path string) string {
	parts := strings.Split(strings.ToLower(path), "/")
	for i, part := range parts {
		if looksLikePathIdentifier(part) {
			parts[i] = ":id"
		}
	}
	return strings.Join(parts, "/")
}

func looksLikePathIdentifier(value string) bool {
	if value == "" {
		return false
	}
	if allDigits(value) {
		return true
	}
	compact := strings.ReplaceAll(value, "-", "")
	if len(compact) != 24 && len(compact) != 32 && len(compact) != 36 {
		return false
	}
	for _, r := range compact {
		if !unicode.IsDigit(r) && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}
