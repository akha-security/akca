package secretscan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// EvidenceJSON builds complete local finding evidence. The exact value is kept
// for reproduction while a masked preview and hash are included for UIs that
// explicitly request redacted output.
func EvidenceJSON(kind, value, sourceURL string, line int) string {
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
	b, _ := json.Marshal(payload)
	return string(b)
}
