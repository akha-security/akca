package report

import (
	"regexp"
	"strings"
)

var (
	reBearer   = regexp.MustCompile(`(?i)(Bearer\s+)[A-Za-z0-9\-._~+/]+=*`)
	reAPIKey   = regexp.MustCompile(`(?i)(api[_-]?key["'\s:=]+)[A-Za-z0-9\-._~+/]{8,}`)
	reJWT      = regexp.MustCompile(`eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+`)
	rePassword = regexp.MustCompile(`(?i)(password["'\s:=]+)[^\s"',;]+`)
	reCookie   = regexp.MustCompile(`(?i)(Cookie:\s*)[^\r\n]+`)
)

func RedactString(s string) string {
	if s == "" {
		return s
	}
	out := s
	out = reBearer.ReplaceAllString(out, `${1}[REDACTED]`)
	out = reAPIKey.ReplaceAllString(out, `${1}[REDACTED]`)
	out = reJWT.ReplaceAllString(out, `[REDACTED_JWT]`)
	out = rePassword.ReplaceAllString(out, `${1}[REDACTED]`)
	out = reCookie.ReplaceAllString(out, `${1}[REDACTED]`)
	return out
}

func RedactFinding(f *FindingEntry) {
	f.Description = RedactString(f.Description)
	f.EvidenceSummary = RedactString(f.EvidenceSummary)
	f.Summary = RedactString(f.Summary)
	f.HTTPEvidence.Payload = RedactString(f.HTTPEvidence.Payload)
	f.HTTPEvidence.RawRequest = RedactString(f.HTTPEvidence.RawRequest)
	f.HTTPEvidence.RawResponse = RedactString(f.HTTPEvidence.RawResponse)
	f.HTTPEvidence.CurlCommand = RedactString(f.HTTPEvidence.CurlCommand)
	f.HTTPEvidence.OASTURL = RedactString(f.HTTPEvidence.OASTURL)
	for i, step := range f.ReproductionSteps {
		f.ReproductionSteps[i] = RedactString(step)
	}
}

func APIKeyRisk(status, service string) string {
	switch strings.ToLower(status) {
	case "valid", "active":
		return "Critical — valid credential for " + service + " may allow unauthorized access"
	case "expired":
		return "Low — expired credential; verify no rotation gaps"
	case "invalid":
		return "Informational — invalid or revoked credential exposed"
	default:
		return "Medium — unknown validation status; manual verification required"
	}
}

func APIKeyRemediation(status, service string) string {
	switch strings.ToLower(status) {
	case "valid", "active":
		return "Revoke and rotate the " + service + " credential immediately; audit access logs"
	case "expired":
		return "Remove expired " + service + " keys from code/config; enforce secret scanning"
	default:
		return "Remove exposed " + service + " credentials from client-side code and rotate if ever valid"
	}
}
