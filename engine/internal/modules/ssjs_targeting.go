package modules

import (
	"net/http"
	"net/url"
	"strings"
	"unicode"
)

// likelyServerSideJSSurface is the bounded fallback used when fingerprinting
// could not identify the backend. Running code-execution and timing payloads on
// every ordinary id/page/filter parameter is both noisy and disproportionately
// expensive. Known Node.js targets remain eligible regardless of parameter name.
func likelyServerSideJSSurface(target ScanTarget) bool {
	for _, module := range target.RecommendedModules {
		if strings.EqualFold(strings.TrimSpace(module), "server_side_js_injection") {
			return true
		}
	}
	parts := []string{
		target.Parameter,
		target.EndpointURL,
		target.EndpointType,
		strings.Join(target.RiskTags, " "),
		target.Profile.ContentType,
		string(target.Profile.Context),
	}
	tokens := strings.FieldsFunc(strings.ToLower(strings.Join(parts, " ")), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	for _, token := range tokens {
		switch token {
		case "code", "eval", "evaluate", "expression", "expr", "script", "javascript", "js",
			"function", "formula", "template", "render", "renderer", "sandbox", "vm", "execute", "exec":
			return true
		}
	}
	return false
}

// ssjsWorkKey collapses crawler variants that exercise the same parameter on
// the same route. Query values and numeric/UUID path identifiers do not justify
// repeating the full RCE/OAST/timing sequence.
func ssjsWorkKey(target ScanTarget) string {
	method := strings.ToUpper(strings.TrimSpace(target.Method))
	if method == "" {
		method = http.MethodGet
	}
	u, err := url.Parse(target.EndpointURL)
	if err != nil {
		return method + "|" + strings.ToLower(target.EndpointURL) + "|" + strings.ToLower(target.Parameter) + "|" + strings.ToLower(target.Location)
	}
	u.RawQuery = ""
	u.Fragment = ""
	parts := strings.Split(strings.ToLower(u.Path), "/")
	for i, part := range parts {
		if ssjsPathIdentifier(part) {
			parts[i] = ":id"
		}
	}
	u.Path = strings.Join(parts, "/")
	u.RawPath = ""
	return method + "|" + strings.ToLower(u.String()) + "|" + strings.ToLower(target.Parameter) + "|" + strings.ToLower(target.Location)
}

func ssjsPathIdentifier(value string) bool {
	if value == "" {
		return false
	}
	allDigits := true
	for _, r := range value {
		if !unicode.IsDigit(r) {
			allDigits = false
			break
		}
	}
	if allDigits {
		return true
	}
	compact := strings.ReplaceAll(value, "-", "")
	if len(compact) != 24 && len(compact) != 32 {
		return false
	}
	for _, r := range compact {
		if !unicode.IsDigit(r) && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func (r *Runner) ssjsTargetLimitPerOrigin() int {
	switch r.cfg.ScanIntensity {
	case "fast":
		return 24
	case "stealth":
		return 12
	default:
		return 48
	}
}
