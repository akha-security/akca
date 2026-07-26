package evidencemarkers

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var (
	sstiMathRe       = regexp.MustCompile(`(\d{1,7})\s*[\*x]\s*(\d{1,7})`)
	unionSentinelRe  = regexp.MustCompile(`\b\d{6,8}\b`)
	commandIDRe      = regexp.MustCompile(`(?i)\buid=\d+(?:\([a-z0-9._-]+\))?\s+gid=\d+(?:\([a-z0-9._-]+\))?(?:\s+groups=\d+(?:\([a-z0-9._-]+\))?(?:,\d+(?:\([a-z0-9._-]+\))?)*)?`)
	commandWinDirRe  = regexp.MustCompile(`(?i)volume serial number is[^\r\n]{0,96}`)
	commandPasswdRe  = regexp.MustCompile(`(?m)^root:[^\r\n]{1,240}:/bin/(?:ba)?sh\s*$`)
	templateErrorRe  = regexp.MustCompile(`(?i)(jinja2\.exceptions|twig\\error|freemarker\.core|template syntax error|undefined filter|templateerror)`)
	xssExecutionRe   = regexp.MustCompile(`(?i)(<script[^>]*>[\s\S]{0,200}?alert\s*\([^<]{0,80}</script>|<svg[^>]{0,240}\bonload\s*=\s*[^>]+>|<img[^>]{0,240}\bonerror\s*=\s*[^>]+>)`)
	generatedTokenRe = regexp.MustCompile(`(?i)^akca[-_][a-z0-9._:\-\[\]]{3,160}$`)
)

var sqlErrorKeywords = []string{
	"you have an error in your sql syntax", "mysql error", "mariadb error",
	"sqlite3.operationalerror", "postgresql error", "pg_query(", "ora-",
	"sqlstate[", "unclosed quotation mark", "quoted string not properly terminated",
	"warning: mysql", "syntax error at or near", "incorrect syntax near",
	"microsoft ole db provider", "odbc sql server driver", "pdoexception",
	"java.sql.sqlexception", "org.postgresql.util.psqlexception", "sql syntax error",
}

var ssrfMarkers = []string{
	"ami-id", "instance-id", "169.254.169.254", "metadata.google", "compute/metadata",
}

var traversalMarkers = []string{
	"root:", "daemon:", "/bin/bash", "/sbin/nologin", "[fonts]", "[extensions]",
	"for 16-bit app support", "[boot loader]", "[operating systems]", "127.0.0.1", "# copyright",
}

// ForResponse returns only typed, baseline-novel proof found in the response.
// It deliberately has no generic body-difference fallback: volatile HTML,
// asset hashes, CDN URLs and bundle names are never vulnerability evidence.
func ForResponse(payload, signal, baselineBody, probeBody, storedMarker string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(marker string) {
		marker = strings.TrimSpace(marker)
		if len(marker) < 2 || !containsFold(probeBody, marker) || containsFold(baselineBody, marker) {
			return
		}
		key := strings.ToLower(marker)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, marker)
	}
	addMatch := func(re *regexp.Regexp) {
		if match := re.FindString(probeBody); match != "" && re.FindString(baselineBody) == "" {
			add(match)
		}
	}

	signalLower := strings.ToLower(strings.TrimSpace(signal))
	if isReflectionSignal(signalLower) {
		add(payload)
		if decoded, err := url.QueryUnescape(payload); err == nil && decoded != payload {
			add(decoded)
		}
	}
	if generatedTokenRe.MatchString(strings.TrimSpace(storedMarker)) {
		add(storedMarker)
	}

	if m := sstiMathRe.FindStringSubmatch(payload); len(m) == 3 &&
		(signalLower == "math_evaluation" || signalLower == "template_evaluation_49") {
		a, _ := strconv.Atoi(m[1])
		b, _ := strconv.Atoi(m[2])
		if a > 1 && b > 1 {
			add(strconv.Itoa(a * b))
		}
	}
	if signalLower == "template_evaluation_49" {
		add("49")
	}

	switch signalLower {
	case "error_based":
		for _, keyword := range sqlErrorKeywords {
			if marker := actualCaseMarker(probeBody, keyword); marker != "" &&
				actualCaseMarker(baselineBody, keyword) == "" {
				add(marker)
			}
		}
	case "error_trace", "config_leak":
		addMatch(templateErrorRe)
	case "command_output", "separator_output":
		addMatch(commandIDRe)
		addMatch(commandWinDirRe)
		addMatch(commandPasswdRe)
	case "classic_entity", "soap_xxe":
		add("AKCA_XXE_TEST")
	case "nosql_auth_bypass":
		for _, marker := range []string{"access_token", "authenticated", "success", "session"} {
			add(actualCaseMarker(probeBody, marker))
		}
	}

	if signalLower == "union_signal" {
		for _, marker := range unionSentinelRe.FindAllString(payload, -1) {
			add(marker)
		}
	}
	if strings.Contains(signalLower, "metadata") || strings.Contains(signalLower, "ssrf") {
		for _, marker := range ssrfMarkers {
			add(actualCaseMarker(probeBody, marker))
		}
		if strings.Contains(strings.ToLower(probeBody), "root:") && strings.Contains(strings.ToLower(probeBody), "/bin/") {
			addMatch(commandPasswdRe)
		}
	}
	if strings.HasPrefix(signalLower, "linux") || strings.HasPrefix(signalLower, "windows") ||
		strings.Contains(signalLower, "traversal") {
		for _, marker := range traversalMarkers {
			add(actualCaseMarker(probeBody, marker))
		}
	}
	if signalLower == "dom_execution" || signalLower == "stored_tracking" || signalLower == "reflected" {
		addMatch(xssExecutionRe)
	}

	return out
}

// ForReport rebuilds safe response proof for both new and legacy findings.
// Legacy arbitrary snippets are ignored. The only persisted markers accepted
// directly are Akca-generated canaries that actually occur in the response.
func ForReport(payload, signal, probeBody string, persisted []string) []string {
	markers := ForResponse(payload, signal, "", probeBody, "")
	seen := make(map[string]struct{}, len(markers))
	for _, marker := range markers {
		seen[strings.ToLower(marker)] = struct{}{}
	}
	for _, marker := range persisted {
		marker = strings.TrimSpace(marker)
		if !generatedTokenRe.MatchString(marker) || !containsFold(probeBody, marker) {
			continue
		}
		key := strings.ToLower(marker)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		markers = append(markers, marker)
	}
	return markers
}

func isReflectionSignal(signal string) bool {
	return signal == "reflected" || signal == "stored_tracking" ||
		signal == "cross_endpoint_trigger" || strings.Contains(signal, "reflected_marker")
}

func containsFold(body, marker string) bool {
	if body == "" || marker == "" {
		return false
	}
	return strings.Contains(body, marker) || strings.Contains(strings.ToLower(body), strings.ToLower(marker))
}

func actualCaseMarker(body, marker string) string {
	if body == "" || marker == "" {
		return ""
	}
	if idx := strings.Index(body, marker); idx >= 0 {
		return body[idx : idx+len(marker)]
	}
	idx := strings.Index(strings.ToLower(body), strings.ToLower(marker))
	if idx < 0 {
		return ""
	}
	return body[idx : idx+len(marker)]
}
