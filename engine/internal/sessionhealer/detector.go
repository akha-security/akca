package sessionhealer

import (
	"strings"
)

var loginPaths = []string{
	"/login", "/signin", "/auth/login", "/api/auth/login",
	"/users/sign_in", "/oauth/login", "/sso",
}

var expiredJSONKeywords = []string{
	"token_expired", "session_expired", "token is expired",
	"jwt expired", "invalid_token", "unauthenticated",
	"session timed out", "signature has expired",
}

// DetectSessionLoss inspects HTTP response status, headers, and body for indicators of session loss.
func DetectSessionLoss(statusCode int, headers map[string]string, body string) (bool, LossReason) {
	// 1. Direct 401 Unauthorized
	if statusCode == 401 {
		return true, ReasonHTTP401
	}

	// 2. Redirect to Login Page (301, 302, 303, 307, 308)
	if statusCode >= 300 && statusCode < 400 {
		for k, v := range headers {
			if strings.EqualFold(k, "Location") {
				locLower := strings.ToLower(v)
				for _, lp := range loginPaths {
					if strings.Contains(locLower, lp) {
						return true, ReasonLoginRedirect
					}
				}
			}
		}
	}

	// 3. JSON error messages indicating token/session expiration
	bodyLower := strings.ToLower(body)
	if statusCode >= 400 && (strings.Contains(bodyLower, `"error"`) || strings.Contains(bodyLower, `"message"`)) {
		for _, kw := range expiredJSONKeywords {
			if strings.Contains(bodyLower, kw) {
				return true, ReasonTokenExpired
			}
		}
	}

	return false, ""
}
