package cloudposture

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Credentials holds cloud auth identifiers leaked in client-side code.
type Credentials struct {
	AWSRegion             string `json:"aws_region,omitempty"`
	CognitoUserPoolID     string `json:"cognito_user_pool_id,omitempty"`
	CognitoClientID       string `json:"cognito_client_id,omitempty"`
	CognitoIdentityPoolID string `json:"cognito_identity_pool_id,omitempty"`
	FirebaseAPIKey        string `json:"firebase_api_key,omitempty"`
	FirebaseProjectID     string `json:"firebase_project_id,omitempty"`
	FirebaseAppID         string `json:"firebase_app_id,omitempty"`
	Auth0Domain           string `json:"auth0_domain,omitempty"`
	Auth0ClientID         string `json:"auth0_client_id,omitempty"`
}

var (
	regionRe            = regexp.MustCompile(`(?i)(?:region|aws_region|awsRegion)\s*[:=]\s*["']((us|eu|ap|sa|ca|me|af)-[\w-]+-\d)["']`)
	userPoolRe          = regexp.MustCompile(`(?i)(?:userPoolId|user_pool_id|UserPoolId)\s*[:=]\s*["']([\w-]+_[0-9A-Za-z]+)["']`)
	clientIDRe          = regexp.MustCompile(`(?i)(?:clientId|client_id|ClientId|appClientId)\s*[:=]\s*["']([0-9a-z]{20,32})["']`)
	identityPoolRe      = regexp.MustCompile(`(?i)(?:identityPoolId|identity_pool_id|IdentityPoolId)\s*[:=]\s*["']([\w-]+:[0-9a-f-]{36})["']`)
	firebaseAPIKeyRe    = regexp.MustCompile(`(?i)(?:apiKey|api_key)\s*[:=]\s*["'](AIza[0-9A-Za-z_\-]{35})["']`)
	firebaseProjectRe   = regexp.MustCompile(`(?i)(?:projectId|project_id)\s*[:=]\s*["']([a-z0-9\-]{4,})["']`)
	firebaseAppIDRe     = regexp.MustCompile(`(?i)(?:appId|app_id)\s*[:=]\s*["'](1:[0-9]+:web:[0-9a-f]+)["']`)
	auth0DomainRe       = regexp.MustCompile(`(?i)(?:domain|auth0Domain)\s*[:=]\s*["']([a-z0-9\-]+\.auth0\.com)["']`)
	cognitoPoolInlineRe = regexp.MustCompile(`\b(us|eu|ap|sa|ca|me|af)-[\w-]+-\d_[0-9A-Za-z]+\b`)
	identityPoolInline  = regexp.MustCompile(`\b(us|eu|ap|sa|ca|me|af)-[\w-]+-\d:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
)

// ExtractCredentials parses JS/config text for cloud auth provider identifiers.
func ExtractCredentials(content string) Credentials {
	var c Credentials
	if m := regionRe.FindStringSubmatch(content); len(m) > 1 {
		c.AWSRegion = m[1]
	}
	if m := userPoolRe.FindStringSubmatch(content); len(m) > 1 {
		c.CognitoUserPoolID = m[1]
		if c.AWSRegion == "" {
			c.AWSRegion = regionFromPoolID(m[1])
		}
	}
	if m := clientIDRe.FindStringSubmatch(content); len(m) > 1 {
		c.CognitoClientID = m[1]
	}
	if m := identityPoolRe.FindStringSubmatch(content); len(m) > 1 {
		c.CognitoIdentityPoolID = m[1]
		if c.AWSRegion == "" {
			c.AWSRegion = regionFromIdentityPool(m[1])
		}
	}
	if c.CognitoUserPoolID == "" {
		if m := cognitoPoolInlineRe.FindString(content); m != "" {
			c.CognitoUserPoolID = m
			c.AWSRegion = regionFromPoolID(m)
		}
	}
	if c.CognitoIdentityPoolID == "" {
		if m := identityPoolInline.FindString(content); m != "" {
			c.CognitoIdentityPoolID = m
			c.AWSRegion = regionFromIdentityPool(m)
		}
	}
	if m := firebaseAPIKeyRe.FindStringSubmatch(content); len(m) > 1 {
		c.FirebaseAPIKey = m[1]
	}
	if m := firebaseProjectRe.FindStringSubmatch(content); len(m) > 1 {
		c.FirebaseProjectID = m[1]
	}
	if m := firebaseAppIDRe.FindStringSubmatch(content); len(m) > 1 {
		c.FirebaseAppID = m[1]
	}
	if m := auth0DomainRe.FindStringSubmatch(content); len(m) > 1 {
		c.Auth0Domain = m[1]
	}
	if c.Auth0ClientID == "" {
		if m := clientIDRe.FindStringSubmatch(content); len(m) > 1 && c.Auth0Domain != "" {
			c.Auth0ClientID = m[1]
		}
	}
	return c
}

func (c Credentials) HasCognito() bool {
	return c.CognitoUserPoolID != "" && c.CognitoClientID != "" && c.AWSRegion != ""
}

func (c Credentials) HasIdentityPool() bool {
	return c.CognitoIdentityPoolID != "" && c.AWSRegion != ""
}

func (c Credentials) HasFirebase() bool {
	return c.FirebaseAPIKey != ""
}

func regionFromPoolID(pool string) string {
	if i := strings.Index(pool, "_"); i > 0 {
		return pool[:i]
	}
	return ""
}

func regionFromIdentityPool(id string) string {
	if i := strings.Index(id, ":"); i > 0 {
		return id[:i]
	}
	return ""
}

// TFStatePaths are common exposed terraform state object keys.
var TFStatePaths = []string{
	"/terraform.tfstate",
	"/terraform.tfstate.backup",
	"/default.tfstate",
	"/prod.tfstate",
	"/staging.tfstate",
	"/dev.tfstate",
	"/infra/terraform.tfstate",
	"/.terraform/terraform.tfstate",
}

// TFStateFinding is a sensitive value extracted from terraform state JSON.
type TFStateFinding struct {
	ResourceType string `json:"resource_type,omitempty"`
	Field        string `json:"field,omitempty"`
	Redacted     string `json:"redacted,omitempty"`
	Severity     string `json:"severity"`
}

var tfSensitiveKeys = []string{
	"password", "secret", "access_key", "secret_key", "connection_string",
	"master_password", "db_password", "private_key", "token", "api_key",
}

// AnalyzeTFState scans terraform state JSON for cleartext secrets and IAM hints.
func AnalyzeTFState(body string) []TFStateFinding {
	body = strings.TrimSpace(body)
	if !strings.HasPrefix(body, "{") {
		return nil
	}
	var root map[string]interface{}
	if err := json.Unmarshal([]byte(body), &root); err != nil {
		return nil
	}
	var out []TFStateFinding
	walkTFValue("", "", root, &out)
	return out
}

func walkTFValue(resourceType, prefix string, v interface{}, out *[]TFStateFinding) {
	switch t := v.(type) {
	case map[string]interface{}:
		if rt, ok := t["type"].(string); ok {
			resourceType = rt
		}
		if res, ok := t["resources"].([]interface{}); ok {
			for _, item := range res {
				walkTFValue("", "", item, out)
			}
		}
		for k, val := range t {
			keyLower := strings.ToLower(k)
			if isTFSensitiveKey(keyLower) {
				if s, ok := val.(string); ok && len(s) > 4 && !isPlaceholder(s) {
					*out = append(*out, TFStateFinding{
						ResourceType: resourceType,
						Field:        prefix + k,
						Redacted:     redact(s),
						Severity:     severityForKey(keyLower),
					})
				}
			}
			walkTFValue(resourceType, prefix+k+".", val, out)
		}
	case []interface{}:
		for i, item := range t {
			walkTFValue(resourceType, prefix+itoa(i)+".", item, out)
		}
	}
}

func isTFSensitiveKey(k string) bool {
	for _, s := range tfSensitiveKeys {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

func severityForKey(k string) string {
	switch {
	case strings.Contains(k, "password"), strings.Contains(k, "secret_key"), strings.Contains(k, "private_key"):
		return "critical"
	case strings.Contains(k, "access_key"), strings.Contains(k, "token"):
		return "high"
	default:
		return "medium"
	}
}

func isPlaceholder(s string) bool {
	lower := strings.ToLower(s)
	for _, p := range []string{"changeme", "example", "xxxx", "your_", "placeholder", "todo"} {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func redact(s string) string {
	if len(s) <= 6 {
		return "***"
	}
	return s[:3] + "..." + s[len(s)-2:]
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	n := len(b)
	v := i
	for v > 0 {
		n--
		b[n] = byte('0' + v%10)
		v /= 10
	}
	return string(b[n:])
}

// IsTFState reports whether body looks like terraform state JSON.
func IsTFState(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, `"terraform_version"`) ||
		(strings.Contains(lower, `"resources"`) && strings.Contains(lower, `"provider"`))
}
