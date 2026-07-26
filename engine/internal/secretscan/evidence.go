package secretscan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// EvidenceJSON builds stored finding evidence. Akca's report policy keeps raw
// evidence intact, so the exact detected value is included alongside a preview
// and hash for correlation.
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
