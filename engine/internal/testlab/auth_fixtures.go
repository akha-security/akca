package testlab

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

var (
	labValidJWT   = buildLabJWT(map[string]interface{}{"alg": "HS256", "typ": "JWT"}, map[string]interface{}{"sub": "akca-user", "role": "user", "exp": float64(4102444800)}, "akca-valid-signature")
	labExpiredJWT = buildLabJWT(map[string]interface{}{"alg": "HS256", "typ": "JWT"}, map[string]interface{}{"sub": "akca-user", "role": "user", "exp": float64(946684800)}, "akca-expired-signature")
)

func LabValidJWT() string   { return labValidJWT }
func LabExpiredJWT() string { return labExpiredJWT }

func buildLabJWT(header, claims map[string]interface{}, signature string) string {
	headerRaw, _ := json.Marshal(header)
	claimsRaw, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(headerRaw) + "." +
		base64.RawURLEncoding.EncodeToString(claimsRaw) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(signature))
}

func decodeLabJWT(token string) (map[string]interface{}, map[string]interface{}, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, false
	}
	decode := func(part string) map[string]interface{} {
		raw, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			return nil
		}
		var value map[string]interface{}
		if json.Unmarshal(raw, &value) != nil {
			return nil
		}
		return value
	}
	header, claims := decode(parts[0]), decode(parts[1])
	return header, claims, header != nil && claims != nil
}
