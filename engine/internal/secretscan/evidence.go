package secretscan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// EvidenceJSON builds complete local finding evidence. The exact value is kept
// for reproduction while a masked preview and hash are included for UIs that
// explicitly request redacted output.
func EvidenceJSON(kind, value, sourceURL string, line int) string {
	return evidenceJSON(kind, value, sourceURL, line, "")
}

// EvidenceJSONWithResponse preserves a bounded excerpt around the detected
// value so reports can show where the secret appeared without storing an
// entire large response a second time.
func EvidenceJSONWithResponse(kind, value, sourceURL string, line int, responseBody string) string {
	return evidenceJSON(kind, value, sourceURL, line, responseBody)
}

func evidenceJSON(kind, value, sourceURL string, line int, responseBody string) string {
	sum := sha256.Sum256([]byte(value))
	payload := map[string]interface{}{
		"secret_kind":    kind,
		"secret_value":   value,
		"secret_preview": Redact(value),
		"secret_sha256":  hex.EncodeToString(sum[:]),
		"source_url":     sourceURL,
	}
	if line > 0 {
		payload["line"] = line
	}
	if excerpt := ResponseSnippet(responseBody, value); excerpt != "" {
		payload["resp_body"] = excerpt
		payload["response_markers"] = []string{value}
		payload["location"] = "response_body"
	}
	b, _ := json.Marshal(payload)
	return string(b)
}

// ResponseSnippet returns a bounded response excerpt centered on marker.
func ResponseSnippet(body, marker string) string {
	const contextWindow = 160
	if body == "" || marker == "" {
		return ""
	}
	idx := strings.Index(body, marker)
	if idx < 0 {
		return ""
	}
	start := idx - contextWindow
	if start < 0 {
		start = 0
	}
	end := idx + len(marker) + contextWindow
	if end > len(body) {
		end = len(body)
	}
	prefix, suffix := "", ""
	if start > 0 {
		prefix = "... "
	}
	if end < len(body) {
		suffix = " ..."
	}
	return prefix + body[start:end] + suffix
}
