package report

import (
	"encoding/json"
	"github.com/akha-security/akca/engine/internal/secretscan"
	"regexp"
	"strings"
)

var secretHeaderRE = regexp.MustCompile(`(?im)((?:authorization|proxy-authorization|cookie|set-cookie|x-api-key)\s*:\s*)[^\r\n]+`)
var secretAssignmentRE = regexp.MustCompile(`(?i)((?:["']?)(?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|secret|token)(?:["']?)\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^&\s,;}]+)`)

func RedactString(s string) string {
	for _, match := range secretscan.Detect(s) {
		if match.Value != "" {
			s = strings.ReplaceAll(s, match.Value, "[REDACTED]")
		}
	}
	s = secretHeaderRE.ReplaceAllString(s, "${1}[REDACTED]")
	return secretAssignmentRE.ReplaceAllString(s, "${1}[REDACTED]")
}

func RedactFinding(f *FindingEntry) {
	if f == nil {
		return
	}
	// Work on a JSON copy so nested evidence and slices cannot retain secrets
	// or mutate the caller's original evidence object.
	raw, err := json.Marshal(f)
	if err != nil {
		return
	}
	var value interface{}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return
	}
	secret := ""
	if f.VulnClass == "secret_exposure" {
		secret = f.HTTPEvidence.Payload
	}
	var clean func(interface{}) interface{}
	clean = func(v interface{}) interface{} {
		switch x := v.(type) {
		case string:
			if secret != "" {
				x = strings.ReplaceAll(x, secret, "[REDACTED]")
			}
			return RedactString(x)
		case []interface{}:
			for i := range x {
				x[i] = clean(x[i])
			}
		case map[string]interface{}:
			for k := range x {
				x[k] = clean(x[k])
			}
		}
		return v
	}
	if raw, err = json.Marshal(clean(value)); err == nil {
		var sanitized FindingEntry
		if json.Unmarshal(raw, &sanitized) == nil {
			*f = sanitized
		}
	}
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
