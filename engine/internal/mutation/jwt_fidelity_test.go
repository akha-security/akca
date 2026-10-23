package mutation

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestJWTMutationHandlesNullAndPreservesNumericClaims(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	for _, claims := range []string{`null`, `[]`, `"text"`, `{"tenant_id":9007199254740993}`} {
		token := header + "." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".signature"
		result := Generate(token, TypeJWT, nil)
		for _, item := range result.Mutations {
			if !strings.Contains(item.Label, "admin role") && !strings.Contains(item.Label, "tampered payload") {
				continue
			}
			raw, _ := base64.RawURLEncoding.DecodeString(strings.Split(item.Value, ".")[1])
			if strings.Contains(claims, "tenant_id") && !strings.Contains(string(raw), "9007199254740993") {
				t.Fatalf("rounded claims: %s", raw)
			}
		}
	}
}
