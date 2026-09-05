package sensitivedata

import (
	"regexp"
	"strconv"
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
	ssnRe              = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	emailRe            = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)
	cardCandidate      = regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)
	jwtRe              = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
	sessionRe          = regexp.MustCompile(`(?i)(?:PHPSESSID|JSESSIONID|connect\.sid|sessionid|ASP\.NET_SessionId)\s*[=:]\s*([A-Za-z0-9._\-]{8,})`)
	internalIPRe       = regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.0\.0\.1)\b`)
	stackTraceRe       = regexp.MustCompile(`(?i)(?:stack trace|traceback \(most recent call last\)|exception in thread|at [\w.$]+\([\w./\\]+:\d+\)|whoops! there was an error|django version:|werkzeug debugger|whitelabel error page|server error in '/' application|system\.web\.httpexception|uncaught exception:|fatal error:.*in /.+ on line \d+)`)
	dbErrorRe          = regexp.MustCompile(`(?i)(?:sql syntax|mysql_fetch|mysqli_|pg_query|sqlite3\.|ORA-\d{5}|unclosed quotation mark|odbc sql server driver|sqlstate\[)`)
	directoryListingRe = regexp.MustCompile(`(?i)(?:<title>Index of /|<h1>Index of /|Directory Listing for /|<a href="[^"]*">\[To Parent Directory\]</a>|<table summary="Directory Listing")`)
	sourceCodeRe       = regexp.MustCompile(`(?m)^\s*(?:import |from .+ import |package |#include |function \w+\(|class \w+|def \w+\()`)
	tcknCandidate      = regexp.MustCompile(`\b[1-9]\d{10}\b`)
	ibanCandidate      = regexp.MustCompile(`(?i)\b(?:[A-Z]{2}\d{2}[A-Z0-9]{11,30}|[A-Z]{2}\d{2}(?:[ -][A-Z0-9]{2,4}){3,8})\b`)
	cardContextRe      = regexp.MustCompile(`(?i)(?:credit[ _-]?card|card[ _-]?(?:number|no)|cc[ _-]?(?:number|no)|payment[ _-]?card|primary[ _-]?account[ _-]?number|\bpan\b|\bvisa\b|mastercard|amex|american express|cardholder|expiry|expiration|\bcvv\b|\bcvc\b)`)
	ibanContextRe      = regexp.MustCompile(`(?i)(?:\biban\b|bank[ _-]?account|account[ _-]?(?:number|no)|beneficiary|\bswift\b|\bbic\b)`)
	fixtureContextRe   = regexp.MustCompile(`(?i)(?:example|sample|dummy|placeholder|fixture|test[ _-]?(?:card|data|mode|number)|sandbox|documentation|docs?|regex|format example|lorem)`)
	phoneRe            = regexp.MustCompile(`\b(?:\+?90|0)?\s*[5][0-9]{2}\s*[0-9]{3}\s*[0-9]{2}\s*[0-9]{2}\b`)
	passportRe         = regexp.MustCompile(`\b[A-Z][0-9]{8}\b`)
	macAddrRe          = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b`)
	ipv6Internal       = regexp.MustCompile(`(?i)\b(?:fe80|fc00|fd00):[0-9a-f:]+\b`)
	dbDumpRe           = regexp.MustCompile(`(?i)(?:CREATE TABLE\s+[a-zA-Z0-9_"` + "`" + `]+|INSERT INTO\s+[a-zA-Z0-9_"` + "`" + `]+\s+VALUES)`)
	graphqlSchema      = regexp.MustCompile(`(?i)type\s+(?:Query|Mutation|Subscription)\s*\{`)
	piiKeywordRe       = regexp.MustCompile(`(?i)\b(?:date[ _-]of[ _-]birth|medical[ _-]record|driver[._]?[s]?[ _-]license|social[ _-]security|passport[ _-]number|tc[ _-]kimlik|anne[ _-]kizlik)\b`)
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
	for _, m := range tcknCandidate.FindAllString(body, 5) {
		if tcknValid(m) {
			add("pii_tckn", m, redactDigits(m), "high", 0.9)
		}
	}
	for _, loc := range ibanCandidate.FindAllStringIndex(body, 5) {
		m := body[loc[0]:loc[1]]
		clean := normalizeIBAN(m)
		if ibanValid(clean) && sensitiveContext(body, loc[0], loc[1], ibanContextRe) {
			add("pii_iban", m, clean[:4]+"***"+clean[len(clean)-4:], "high", 0.98)
		}
	}
	if piiKeywordRe.MatchString(body) {
		lowerBody := strings.ToLower(body)
		isHTML := strings.Contains(lowerBody, "<html") || strings.Contains(lowerBody, "<!doctype")
		// Only alert on PII keywords in JSON/API payloads or non-HTML data, not bare HTML form labels or policy text
		if !isHTML || strings.Contains(lowerBody, "application/json") {
			add("pii_context", piiKeywordRe.FindString(body), "[PII keyword]", "medium", 0.7)
		}
	}
	for _, m := range emailRe.FindAllString(body, 5) {
		if strings.Contains(strings.ToLower(m), "example.com") || isPublicRoleEmail(m) {
			continue
		}
		add("pii_email", m, redactEmail(m), "medium", 0.55)
	}
	for _, loc := range cardCandidate.FindAllStringIndex(body, 3) {
		m := body[loc[0]:loc[1]]
		digits := digitsOnly(m)
		if len(digits) < 13 || len(digits) > 19 {
			continue
		}
		if !luhnValid(digits) || !cardIssuerAndLengthValid(digits) || lowDiversityDigits(digits) || knownTestPAN(digits) {
			continue
		}
		if !sensitiveContext(body, loc[0], loc[1], cardContextRe) {
			continue
		}
		add("credit_card", m, redactDigits(digits), "critical", 0.99)
	}
	for _, m := range jwtRe.FindAllString(body, 3) {
		add("jwt_token", m, redactToken(m), "high", 0.8)
	}
	if sm := sessionRe.FindStringSubmatch(body); len(sm) > 1 {
		add("session_id", sm[0], redactToken(sm[1]), "high", 0.75)
	}
	for _, m := range internalIPRe.FindAllString(body, 5) {
		if m == "127.0.0.1" {
			continue
		}
		add("internal_ip", m, m, "high", 0.8)
	}
	for _, m := range phoneRe.FindAllString(body, 3) {
		add("pii_phone", m, redactToken(m), "medium", 0.7)
	}
	for _, m := range passportRe.FindAllString(body, 3) {
		add("pii_passport", m, redactToken(m), "high", 0.85)
	}
	for _, m := range macAddrRe.FindAllString(body, 3) {
		add("mac_address", m, m, "medium", 0.65)
	}
	for _, m := range ipv6Internal.FindAllString(body, 3) {
		add("internal_ipv6", m, m, "high", 0.8)
	}
	if m := dbDumpRe.FindString(body); m != "" {
		add("database_dump_leak", m, "[SQL DUMP]", "critical", 0.95)
	}
	if m := graphqlSchema.FindString(body); m != "" {
		add("graphql_schema_exposure", m, "[GraphQL Schema]", "medium", 0.75)
	}
	if stackTraceRe.MatchString(body) {
		add("stack_trace", stackTraceRe.FindString(body), "[stack trace]", "high", 0.85)
	}
	if dbErrorRe.MatchString(body) {
		add("database_error", dbErrorRe.FindString(body), "[db error]", "high", 0.8)
	}
	if directoryListingRe.MatchString(body) {
		add("directory_listing", directoryListingRe.FindString(body), "[directory listing enabled]", "medium", 0.9)
	}
	if sourceCodeRe.MatchString(body) && looksLikeSourceLeak(body) {
		add("source_code_snippet", sourceCodeRe.FindString(body), "[source snippet]", "medium", 0.65)
	}

	return out
}

func sensitiveContext(body string, start, end int, positive *regexp.Regexp) bool {
	windowStart := start - 96
	if windowStart < 0 {
		windowStart = 0
	}
	windowEnd := end + 96
	if windowEnd > len(body) {
		windowEnd = len(body)
	}
	window := body[windowStart:windowEnd]
	return positive.MatchString(window) && !fixtureContextRe.MatchString(window)
}

func normalizeIBAN(value string) string {
	var out strings.Builder
	for _, r := range strings.ToUpper(value) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			out.WriteRune(r)
		}
	}
	return out.String()
}

var ibanCountryLengths = map[string]int{
	"AL": 28, "AD": 24, "AT": 20, "AZ": 28, "BH": 22, "BE": 16, "BA": 20, "BR": 29, "BG": 22, "CR": 22, "HR": 21, "CY": 28, "CZ": 24,
	"DK": 18, "DO": 28, "EE": 20, "FO": 18, "FI": 18, "FR": 27, "GE": 22, "DE": 22, "GI": 23, "GR": 27, "GL": 18, "GT": 28, "HU": 28, "IS": 26,
	"IE": 22, "IL": 23, "IT": 27, "JO": 30, "KZ": 20, "XK": 20, "KW": 30, "LV": 21, "LB": 28, "LI": 21, "LT": 20, "LU": 20, "MK": 19, "MT": 31,
	"MR": 27, "MU": 30, "MC": 27, "MD": 24, "ME": 22, "NL": 18, "NO": 15, "PK": 24, "PS": 29, "PL": 28, "PT": 25, "QA": 29, "RO": 24, "LC": 32,
	"SM": 27, "ST": 25, "SA": 24, "RS": 22, "SC": 31, "SK": 24, "SI": 19, "ES": 24, "SE": 24, "CH": 21, "TL": 23, "TN": 24, "TR": 26, "UA": 29,
	"AE": 23, "GB": 22, "VA": 22, "VG": 24, "IQ": 23, "BY": 28, "EG": 29, "LY": 25, "SD": 18, "BI": 27, "DJ": 27, "RU": 33, "SO": 23, "SV": 28,
	"NI": 32, "MN": 20, "FK": 18, "OM": 23,
}

func ibanValid(value string) bool {
	if len(value) < 15 || len(value) > 34 || len(value) < 4 {
		return false
	}
	expected, ok := ibanCountryLengths[value[:2]]
	if !ok || len(value) != expected {
		return false
	}
	if value[2] < '0' || value[2] > '9' || value[3] < '0' || value[3] > '9' {
		return false
	}
	rearranged := value[4:] + value[:4]
	remainder := 0
	for _, r := range rearranged {
		if r >= '0' && r <= '9' {
			remainder = (remainder*10 + int(r-'0')) % 97
			continue
		}
		if r < 'A' || r > 'Z' {
			return false
		}
		n := int(r-'A') + 10
		remainder = (remainder*100 + n) % 97
	}
	return remainder == 1
}

func cardIssuerAndLengthValid(pan string) bool {
	length := len(pan)
	prefix := func(n int) int {
		if len(pan) < n {
			return -1
		}
		value, err := strconv.Atoi(pan[:n])
		if err != nil {
			return -1
		}
		return value
	}
	switch {
	case pan[0] == '4':
		return length == 13 || length == 16 || length == 19
	case prefix(2) == 34 || prefix(2) == 37:
		return length == 15
	case prefix(2) >= 51 && prefix(2) <= 55:
		return length == 16
	case prefix(4) >= 2221 && prefix(4) <= 2720:
		return length == 16
	case prefix(4) == 6011 || prefix(2) == 65 || (prefix(3) >= 644 && prefix(3) <= 649):
		return length == 16 || length == 19
	case prefix(4) >= 3528 && prefix(4) <= 3589:
		return length >= 16 && length <= 19
	case (prefix(3) >= 300 && prefix(3) <= 305) || prefix(2) == 36 || prefix(2) == 38 || prefix(2) == 39:
		return length == 14
	case prefix(2) == 62:
		return length >= 16 && length <= 19
	default:
		return false
	}
}

func lowDiversityDigits(value string) bool {
	seen := map[byte]struct{}{}
	for i := range value {
		seen[value[i]] = struct{}{}
	}
	return len(seen) < 4
}

func knownTestPAN(value string) bool {
	switch value {
	case "4111111111111111", "4242424242424242", "4000000000000002",
		"5555555555554444", "5105105105105100", "378282246310005",
		"371449635398431", "6011111111111117", "30569309025904",
		"3530111333300000", "3566002020360505", "2223003122003222":
		return true
	default:
		return false
	}
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

func tcknValid(digits string) bool {
	if len(digits) != 11 || digits[0] == '0' {
		return false
	}
	var d [11]int
	for i := 0; i < 11; i++ {
		d[i] = int(digits[i] - '0')
	}

	oddSum := d[0] + d[2] + d[4] + d[6] + d[8]
	evenSum := d[1] + d[3] + d[5] + d[7]

	c10 := ((oddSum * 7) - evenSum) % 10
	if c10 < 0 {
		c10 += 10
	}
	if d[9] != c10 {
		return false
	}

	c11 := (oddSum + evenSum + d[9]) % 10
	return d[10] == c11
}

func isPublicRoleEmail(email string) bool {
	lower := strings.ToLower(email)
	prefix := lower
	if idx := strings.Index(lower, "@"); idx != -1 {
		prefix = lower[:idx]
	}
	roles := []string{"support", "info", "contact", "sales", "help", "hello", "press", "billing", "privacy", "security", "jobs", "careers", "marketing", "admin", "team", "service", "inquiry", "feedback"}
	for _, r := range roles {
		if prefix == r || strings.HasPrefix(prefix, r+".") || strings.HasPrefix(prefix, r+"-") || strings.HasPrefix(prefix, r+"_") {
			return true
		}
	}
	return false
}
