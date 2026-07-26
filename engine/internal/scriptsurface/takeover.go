package scriptsurface

import "strings"

// AnalyzeResponse checks whether a third-party resource response indicates broken link / takeover risk.
func AnalyzeResponse(status int, body string) (ok bool, signal string) {
	lower := strings.ToLower(body)
	for _, kw := range []string{
		"there isn't a github pages site here",
		"no such bucket", "bucket does not exist", "nosuchbucket",
		"herokucdn.com/error-pages", "no such app", "fastly error",
		"repository not found", "project not found",
		"the specified bucket does not exist",
	} {
		if strings.Contains(lower, kw) {
			if status == 404 || status == 410 {
				return true, "broken_cdn_takeover"
			}
			return true, "broken_external_resource"
		}
	}
	switch {
	case status == 404 || status == 410:
		return true, "broken_external_resource"
	case status >= 500 && strings.Contains(lower, "amazonaws"):
		return true, "s3_misconfiguration"
	}
	return false, ""
}
