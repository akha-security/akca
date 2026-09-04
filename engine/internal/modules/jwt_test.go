package modules

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func sampleValidJWT() string {
	header := `{"alg":"HS256","typ":"JWT"}`
	payload := `{"sub":"user123","role":"user","email":"user@example.com"}`
	hb := base64.RawURLEncoding.EncodeToString([]byte(header))
	pb := base64.RawURLEncoding.EncodeToString([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString([]byte("signature"))
	return hb + "." + pb + "." + sig
}

func TestTamperJWTUnverifiedSignature(t *testing.T) {
	tok := sampleValidJWT()
	tampered, ok := tamperJWTUnverifiedSignature(tok, "akca-admin")
	if !ok {
		t.Fatal("expected tamperJWTUnverifiedSignature to succeed")
	}
	parts := strings.Split(tampered, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload error: %v", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		t.Fatalf("unmarshal claims error: %v", err)
	}
	if claims["sub"] != "akca-admin" || claims["admin"] != true {
		t.Fatalf("expected admin claims, got %v", claims)
	}
}

func TestTamperJWTNoneMatrix(t *testing.T) {
	tok := sampleValidJWT()
	matrix := tamperJWTNoneMatrix(tok, "akca-admin")
	if len(matrix) == 0 {
		t.Fatal("expected none matrix to produce items")
	}
	seen := map[string]bool{}
	for _, item := range matrix {
		seen[item.name] = true
		if item.token == "" {
			t.Fatalf("token for %s is empty", item.name)
		}
	}
	for _, expected := range []string{"alg_none", "alg_None", "alg_NONE", "alg_nOnE"} {
		if !seen[expected] {
			t.Errorf("missing matrix item: %s", expected)
		}
	}
}

func TestTamperJWTJWK(t *testing.T) {
	tok := sampleValidJWT()
	tampered, ok := tamperJWTJWK(tok, "akca-admin")
	if !ok {
		t.Fatal("expected tamperJWTJWK to succeed")
	}
	parts := strings.Split(tampered, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}
	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header error: %v", err)
	}
	var header map[string]interface{}
	if err := json.Unmarshal(hdrBytes, &header); err != nil {
		t.Fatalf("unmarshal header error: %v", err)
	}
	if header["alg"] != "RS256" {
		t.Fatalf("expected alg RS256, got %v", header["alg"])
	}
	jwk, ok := header["jwk"].(map[string]interface{})
	if !ok || jwk["kty"] != "RSA" || jwk["n"] == "" {
		t.Fatalf("expected valid RSA jwk in header, got %v", header["jwk"])
	}
}

func TestTamperJWTX5C(t *testing.T) {
	tok := sampleValidJWT()
	tampered, ok := tamperJWTX5C(tok, "akca-admin")
	if !ok {
		t.Fatal("expected tamperJWTX5C to succeed")
	}
	parts := strings.Split(tampered, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}
	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header error: %v", err)
	}
	var header map[string]interface{}
	if err := json.Unmarshal(hdrBytes, &header); err != nil {
		t.Fatalf("unmarshal header error: %v", err)
	}
	x5c, ok := header["x5c"].([]interface{})
	if !ok || len(x5c) == 0 {
		t.Fatalf("expected x5c certificate chain, got %v", header["x5c"])
	}
}

func TestTamperJWTKid(t *testing.T) {
	tok := sampleValidJWT()
	tampered, ok := tamperJWTKid(tok, "akca-admin", "../../../../dev/null", "")
	if !ok {
		t.Fatal("expected tamperJWTKid to succeed")
	}
	parts := strings.Split(tampered, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}
	hdrBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header map[string]interface{}
	_ = json.Unmarshal(hdrBytes, &header)
	if header["kid"] != "../../../../dev/null" {
		t.Fatalf("expected kid traversal, got %v", header["kid"])
	}
}

func TestExtractJWTFromCookieHeader(t *testing.T) {
	tok := sampleValidJWT()
	cookie := "session=123; auth_token=" + tok + "; theme=dark"
	extracted := extractJWTFromCookieHeader(cookie)
	if extracted != tok {
		t.Fatalf("expected %s, got %s", tok, extracted)
	}
}
