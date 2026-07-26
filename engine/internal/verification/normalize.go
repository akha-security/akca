package verification

import "regexp"

var (
	volatileTimestampRE = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b|\b\d{10,13}\b`)
	volatileUUIDRE      = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	volatileTokenRE     = regexp.MustCompile(`(?i)\b(?:csrf|csrf_?token|xsrf|xsrf_?token|token|request_?id|trace_?id|session_?id|sid)\b(['"]?\s*[:=]\s*['"]?)[a-zA-Z0-9._~-]{16,}`)
)

// NormalizeVolatileFields removes common per-request values before response
// comparisons. All verification paths use this single normalization policy.
func NormalizeVolatileFields(body string) string {
	body = volatileTimestampRE.ReplaceAllString(body, "__TS__")
	body = volatileUUIDRE.ReplaceAllString(body, "__UUID__")
	body = volatileTokenRE.ReplaceAllString(body, "__VOLATILE__")
	return body
}
