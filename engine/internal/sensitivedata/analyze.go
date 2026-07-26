package sensitivedata

import (
	"regexp"
	"strings"
)

// Finding is a contextual sensitive data leak in an HTTP response body.
type Finding struct {
	Kind     string  `json:"kind"`
	Match    string  `json:"match"`
	Redacted string  `json:"redacted"`
	Severity string  `json:"severity"`
	Score    float64 `json:"score"`
}

var (
	ssnRe          = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	emailRe        = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)
	cardCandidate  = regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)
	jwtRe          = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
	sessionRe      = regexp.MustCompile(`(?i)(?:PHPSESSID|JSESSIONID|connect\.sid|sessionid|ASP\.NET_SessionId)\s*[=:]\s*([A-Za-z0-9._\-]{8,})`)
	internalIPRe   = regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.0\.0\.1)\b`)
	stackTraceRe   = regexp.MustCompile(`(?i)(?:stack trace|traceback \(most recent call last\)|exception in thread|at [\w.$]+\([\w./\\]+:\d+\))`)
	dbErrorRe      = regexp.MustCompile(`(?i)(?:sql syntax|mysql_fetch|mysqli_|pg_query|sqlite3\.|ORA-\d{5}|unclosed quotation mark|odbc sql server driver|sqlstate\[)`)
	sourceCodeRe   = regexp.MustCompile(`(?m)^\s*(?:import |from .+ import |package |#include |function \w+\(|class \w+|def \w+\()`)
	piiKeywordRe   = regexp.MustCompile(`(?i)\b(?:date of birth|medical record|driver.?s license|social security|passport number)\b`)
)

// Analyze scans response bodies for semantically sensitive data exposure.
func Analyze(body string) []Finding {
	if strings.TrimSpace(body) == "" {
		return nil
	}
	var out []Finding
	seen := map[string]struct{}{}

	add := func(kind, match, redacted, severity string, score float64) {
		key := kind + "|" + redacted
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, Finding{Kind: kind, Match: match, Redacted: redacted, Severity: severity, Score: score})
	}

	for _, m := range ssnRe.FindAllString(body, -1) {
		add("pii_ssn", m, redactDigits(m), "high", 0.85)
	}
	if piiKeywordRe.MatchString(body) {
		add("pii_context", piiKeywordRe.FindString(body), "[PII keyword]", "medium", 0.7)
	}
	for _, m := range emailRe.FindAllString(body, 5) {
		if strings.Contains(strings.ToLower(m), "example.com") {
			continue
		}
		add("pii_email", m, redactEmail(m), "medium", 0.55)
	}
	for _, m := range cardCandidate.FindAllString(body, 3) {
		digits := digitsOnly(m)
		if len(digits) < 13 || len(digits) > 19 {
			continue
		}
		if !luhnValid(digits) {
			continue
		}
		add("credit_card", m, redactDigits(digits), "critical", 0.95)
	}
	for _, m := range jwtRe.FindAllString(body, 3) {
		add("jwt_token", m, redactToken(m), "high", 0.8)
	}
	if sm := sessionRe.FindStringSubmatch(body); len(sm) > 1 {
		add("session_id", sm[0], redactToken(sm[1]), "high", 0.75)
	}
	for _, m := range internalIPRe.FindAllString(body, 5) {
		if m == "127.0.0.1" {
			add("internal_ip", m, m, "medium", 0.6)
		} else {
			add("internal_ip", m, m, "high", 0.8)
		}
	}
	if stackTraceRe.MatchString(body) {
		add("stack_trace", stackTraceRe.FindString(body), "[stack trace]", "high", 0.85)
	}
	if dbErrorRe.MatchString(body) {
		add("database_error", dbErrorRe.FindString(body), "[db error]", "high", 0.8)
	}
	if sourceCodeRe.MatchString(body) && looksLikeSourceLeak(body) {
		add("source_code_snippet", sourceCodeRe.FindString(body), "[source snippet]", "medium", 0.65)
	}

	return out
}

func looksLikeSourceLeak(body string) bool {
	lower := strings.ToLower(body)
	if strings.Contains(lower, "<html") && strings.Count(body, "\n") < 3 {
		return false
	}
	hits := 0
	for _, kw := range []string{"import ", "function ", "class ", "def ", "#include", "package "} {
		if strings.Contains(body, kw) {
			hits++
		}
	}
	return hits >= 1 && (strings.Contains(lower, "error") || strings.Contains(lower, "exception") || hits >= 2)
}

func luhnValid(digits string) bool {
	sum, alt := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		n := int(digits[i] - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func redactDigits(s string) string {
	d := digitsOnly(s)
	if len(d) <= 4 {
		return "****"
	}
	return strings.Repeat("*", len(d)-4) + d[len(d)-4:]
}

func redactEmail(s string) string {
	at := strings.Index(s, "@")
	if at <= 1 {
		return "[email]"
	}
	return s[:1] + "***" + s[at:]
}

func redactToken(s string) string {
	if len(s) <= 8 {
		return "[token]"
	}
	return s[:4] + "..." + s[len(s)-4:]
}
