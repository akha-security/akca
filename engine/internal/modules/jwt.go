package modules

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/verification"
)

func (r *Runner) runJWT(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("jwt", target); !ok {
		r.emitSkip("jwt", target, reason)
		return nil
	}
	validToken := capturedJWT(r.cfg)
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
	invalidToken := invalidateJWTSignature(validToken)
	invalid, err := r.probeWithHeaders(ctx, target, "", map[string]string{"Authorization": "Bearer " + invalidToken})
	if err != nil || jwtIdentityFromResponse(invalid.Response) == validIdentity {
		return nil
	}
	expiredToken := capturedExpiredJWT(r.cfg)
	if expiredToken == "" {
		r.emitSkip("jwt", target, "JWT proof requires a captured, validly signed expired-token control")
		return nil
	}
	expired, err := r.probeWithHeaders(ctx, target, "", map[string]string{"Authorization": "Bearer " + expiredToken})
	if err != nil || jwtIdentityFromResponse(expired.Response) == validIdentity {
		return nil
	}
	tampered, ok := tamperJWTNone(validToken, "akca-admin")
	if !ok {
		return nil
	}
	probe, err := r.probeWithHeaders(ctx, target, "", map[string]string{"Authorization": "Bearer " + tampered})
	if err != nil || probe.Response.StatusCode < 200 || probe.Response.StatusCode >= 300 {
		return nil
	}
	probeIdentity := jwtIdentityFromResponse(probe.Response)
	if probeIdentity == "" || probeIdentity == validIdentity || !strings.Contains(strings.ToLower(probeIdentity), "akca-admin") {
		return nil
	}
	payload := defaultPayload("jwt", "alg_none", tampered, "identity_change_confirmed")
	finding := r.verifyAndBuildWithCandidate(ctx, "jwt", target, payload, valid, probe,
		"identity_change_confirmed", false, false, "", "", func(candidate *verification.Candidate) {
			candidate.RequestedProofType = verification.ProofIdentityBoundary
			candidate.NegativeControlSet = true
			candidate.NegativeControlOK = true
			candidate.Observations = append(candidate.Observations,
				r.identityObservation("jwt", target, verification.RoleIdentityA, 1, validIdentity, valid),
				r.identityObservation("jwt", target, verification.RoleIdentityB, 1, probeIdentity, probe),
				r.identityObservation("jwt", target, verification.RoleAnonymousControl, 1, "invalid_signature", invalid),
				r.identityObservation("jwt", target, verification.RoleExpiredSessionControl, 1, "expired_token", expired),
			)
		})
	if finding == nil {
		return nil
	}
	finding.Description = "A captured valid JWT established the original identity; invalid-signature and validly signed expired-token controls were rejected; an alg:none token changed the protected endpoint identity."
	var out []ModuleFinding
	r.recordFinding(&out, finding, "jwt", "identity_change_confirmed")
	return out
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
	return len(parts) == 3 && decodeJWTPart(parts[0]) != nil && decodeJWTPart(parts[1]) != nil
}

func invalidateJWTSignature(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	parts[2] = base64.RawURLEncoding.EncodeToString([]byte("akca-invalid-signature"))
	return strings.Join(parts, ".")
}

func tamperJWTNone(token, identity string) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", false
	}
	header := decodeJWTPart(parts[0])
	claims := decodeJWTPart(parts[1])
	if header == nil || claims == nil {
		return "", false
	}
	header["alg"] = "none"
	claims["sub"] = identity
	claims["role"] = identity
	headerRaw, _ := json.Marshal(header)
	claimsRaw, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(headerRaw) + "." +
		base64.RawURLEncoding.EncodeToString(claimsRaw) + ".", true
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
