package report

import "strings"

func RedactString(s string) string {
	return s
}

func RedactFinding(f *FindingEntry) {
}

func APIKeyRisk(status, service string) string {
	switch strings.ToLower(status) {
	case "valid", "active":
		return "Critical - valid credential for " + service + " may allow unauthorized access"
	case "expired":
		return "Low - expired credential; verify no rotation gaps"
	case "invalid":
		return "Informational - invalid or revoked credential exposed"
	default:
		return "Medium - unknown validation status; manual verification required"
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
