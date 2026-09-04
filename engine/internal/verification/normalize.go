package verification

import "regexp"

var (
	volatileTimestampRE  = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b|(?i:(?:timestamp|time|date|created|updated|modified|expires|issued|generated|_at|_on)\s*["':=]\s*)(\d{10,13})\b`)
	volatileUUIDRE       = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	volatileTokenRE      = regexp.MustCompile(`(?i)\b(?:csrf|csrf_?token|xsrf|xsrf_?token|token|request_?id|trace_?id|session_?id|sid|nonce|state|authenticity_token|__RequestVerificationToken|_token|anti_?forgery)\b(['"]?\s*[:=]\s*['"]?)[a-zA-Z0-9._~-]{8,}`)
	volatileHiddenRE     = regexp.MustCompile(`(?i)<input[^>]+name=["']?(?:csrf|xsrf|_token|nonce|authenticity_token|token)[^>]+value=["']?([a-zA-Z0-9._~-]+)["']?`)
	volatileHexHashRE    = regexp.MustCompile(`\b[0-9a-fA-F]{32,64}\b`)
	volatileNumericSeqRE = regexp.MustCompile(`(?i)\b(?:count|counter|seq|sequence|rand|random|nonce|ticket|timestamp)\b\s*[:=]\s*\d+\b`)
)

// NormalizeVolatileFields removes common per-request values before response
// comparisons. All verification paths use this single normalization policy.
func NormalizeVolatileFields(body string) string {
	body = volatileTimestampRE.ReplaceAllString(body, "__TS__")
	body = volatileUUIDRE.ReplaceAllString(body, "__UUID__")
	body = volatileHiddenRE.ReplaceAllString(body, "__CSRF_HIDDEN__")
	body = volatileTokenRE.ReplaceAllString(body, "__VOLATILE__")
	body = volatileHexHashRE.ReplaceAllString(body, "__HASH__")
	body = volatileNumericSeqRE.ReplaceAllString(body, "__SEQ__")
	return body
}
