package jsanalyzer

import "github.com/akha-security/akca/engine/internal/secretscan"

// DetectSecrets scans JavaScript content for leaked secrets/credentials. The
// underlying detection lives in the shared secretscan package so the crawler
// and JS analyzer use identical, high-coverage signatures.
func DetectSecrets(js string) []SecretMatch {
	matches := secretscan.Detect(js)
	out := make([]SecretMatch, 0, len(matches))
	for _, m := range matches {
		out = append(out, SecretMatch{
			Kind: m.Kind, Value: m.Value, Redacted: m.Redacted, Confidence: m.Confidence, LineHint: m.Line,
		})
	}
	return out
}

// RedactSecret masks a raw secret value, retained for backward compatibility.
func RedactSecret(raw string) string {
	return secretscan.Redact(raw)
}
