package bypass403

import (
	"regexp"
	"strings"
)

var (
	compareScriptRE = regexp.MustCompile(`(?is)<(?:script|style)\b[^>]*>.*?</(?:script|style)>`)
	compareTagRE    = regexp.MustCompile(`(?s)<[^>]+>`)
	compareUUIDRE   = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b`)
	compareHashRE   = regexp.MustCompile(`(?i)\b(?:[a-f0-9]{12,}|[a-z0-9]{8,}-[a-z0-9_-]{4,})\b`)
	compareTimeRE   = regexp.MustCompile(`(?i)\b\d{4}-\d{2}-\d{2}[t ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:z|[+-]\d{2}:?\d{2})?\b|\b\d{10,13}\b`)
	compareNumberRE = regexp.MustCompile(`\b\d{4,}\b`)
	compareSpaceRE  = regexp.MustCompile(`\s+`)
	denialTitleRE   = regexp.MustCompile(`(?is)<title[^>]*>[^<]*(?:access denied|forbidden|unauthorized|not found|sign[ -]?in|log[ -]?in|security check|attention required|request blocked|error)[^<]*</title>`)
	loginFormRE     = regexp.MustCompile(`(?is)<form[^>]*(?:login|signin|auth)[^>]*>.*?<input[^>]+type=["']?password`)
)

const maxComparisonBodyBytes = 128 * 1024

// IsMeaningfulBypass is the cheap first-stage filter. A positive result is
// only a candidate; Engine still requires a paired negative control and a
// reproducible second positive response before publishing a finding.
func IsMeaningfulBypass(baseline Baseline, status int, body string) (bool, string) {
	if status == baseline.StatusCode && bodiesSimilar(baseline.Body, body) {
		return false, "same_status_and_body"
	}

	switch {
	case status == 401:
		return false, "still_unauthorized"
	case status == 403:
		// 401 -> 403 remains access denied; it is not an authentication bypass.
		return false, "still_forbidden"
	case status == 404, status == 405, status == 410, status == 429:
		return false, "non_access_status"
	case status >= 300 && status < 400:
		// Redirects commonly point to login/challenge pages. The HTTP client may
		// follow them, but an unresolved 3xx is never direct access proof.
		return false, "redirect_without_access_proof"
	case status >= 500:
		return false, "server_error"
	case status != 200:
		return false, "unclassified_status"
	}

	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return false, "empty_200"
	}
	if bodiesSimilar(baseline.Body, body) {
		return false, "same_body_on_200"
	}
	if looksLikeDeniedOrErrorPage(body) {
		return false, "denial_or_challenge_page"
	}
	if isTrivialSuccessBody(trimmed) {
		return false, "trivial_200_without_resource_evidence"
	}
	return true, "ok_access"
}

func bodiesSimilar(a, b string) bool {
	if a == b {
		return true
	}
	an := normalizeComparisonBody(a)
	bn := normalizeComparisonBody(b)
	if an == bn {
		return true
	}
	if an == "" || bn == "" {
		return false
	}
	lengthRatio := float64(min(len(an), len(bn))) / float64(max(len(an), len(bn)))
	if lengthRatio < 0.55 {
		return false
	}
	return tokenSimilarity(an, bn) >= 0.82
}

func normalizeComparisonBody(body string) string {
	body = comparisonSample(body)
	body = strings.ToLower(body)
	body = compareScriptRE.ReplaceAllString(body, " ")
	body = compareTagRE.ReplaceAllString(body, " ")
	body = compareUUIDRE.ReplaceAllString(body, " <id> ")
	body = compareHashRE.ReplaceAllString(body, " <hash> ")
	body = compareTimeRE.ReplaceAllString(body, " <time> ")
	body = compareNumberRE.ReplaceAllString(body, " <number> ")
	return strings.TrimSpace(compareSpaceRE.ReplaceAllString(body, " "))
}

func comparisonSample(body string) string {
	if len(body) <= maxComparisonBodyBytes {
		return body
	}
	half := maxComparisonBodyBytes / 2
	return body[:half] + " " + body[len(body)-half:]
}

func tokenSimilarity(a, b string) float64 {
	left := tokenSet(a)
	right := tokenSet(b)
	if len(left) == 0 || len(right) == 0 {
		return 0
	}
	intersection := 0
	for token := range left {
		if _, ok := right[token]; ok {
			intersection++
		}
	}
	union := len(left) + len(right) - intersection
	if union == 0 {
		return 1
	}
	return float64(intersection) / float64(union)
}

func tokenSet(value string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, token := range strings.FieldsFunc(value, func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '_' && r != '-'
	}) {
		if len(token) >= 2 {
			out[token] = struct{}{}
		}
	}
	return out
}

func looksLikeDeniedOrErrorPage(body string) bool {
	lower := strings.ToLower(strings.TrimSpace(body))
	if lower == "" {
		return true
	}
	if denialTitleRE.MatchString(body) || loginFormRE.MatchString(body) {
		return true
	}
	for _, marker := range []string{
		"cf-chl-", "cloudflare ray id", "attention required!", "checking your browser",
		"akamai bot manager", "incapsula incident id", "imperva incident id",
		"request rejected", "request blocked", "web application firewall", "captcha",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	// Short text/JSON responses are often soft denial pages returned with 200.
	if len(lower) <= 8192 {
		for _, marker := range []string{
			"access denied", "permission denied", "authentication required", "login required",
			"please log in", "please login", "not authorized", "unauthorized request",
			"invalid token", "missing token", "forbidden", "resource not found", "page not found",
		} {
			if strings.Contains(lower, marker) {
				return true
			}
		}
	}
	return false
}

func looksLikeInfrastructureChallenge(body string) bool {
	lower := strings.ToLower(comparisonSample(strings.TrimSpace(body)))
	if lower == "" {
		return false
	}
	for _, marker := range []string{
		"cf-chl-", "cloudflare ray id", "attention required!", "checking your browser",
		"akamai bot manager", "incapsula incident id", "imperva incident id",
		"web application firewall", "captcha", "bot detection", "ddos-guard",
		"datadome", "perimeterx", "akamai ghost",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func isTrivialSuccessBody(body string) bool {
	compact := strings.ToLower(strings.Trim(strings.TrimSpace(body), `"'`))
	switch compact {
	case "ok", "success", "true", "accepted", "done", "{}", "[]", "null":
		return true
	}
	return len(compact) < 8
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
