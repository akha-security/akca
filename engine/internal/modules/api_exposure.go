package modules

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/secretscan"
	"github.com/akha-security/akca/engine/internal/sensitivedata"
)

func (r *Runner) runAPIExposure(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("api_exposure", target); !ok {
		r.emitSkip("api_exposure", target, reason)
		return nil
	}
	if !r.endpointModuleOnce("api_exposure", target) {
		return nil
	}
	var out []ModuleFinding
	rr, err := r.cachedEmptyProbe(ctx, target)
	if err != nil {
		return nil
	}
	signal, field := apiExposureSignal(rr.Response.Body)
	if signal == "" {
		return nil
	}
	if !apiExposureResponseSurface(target.EndpointURL, rr.Response) {
		r.emitOnce("api-exposure-surface:"+target.EndpointURL, "module_notice",
			"API exposure content marker ignored because response does not look like an API payload",
			map[string]interface{}{
				"module":   "api_exposure",
				"endpoint": target.EndpointURL,
				"status":   rr.Response.StatusCode,
			})
		return nil
	}
	baseline := httpclient.RequestResponse{
		Response: httpclient.ResponseRecord{StatusCode: 200, Body: "{}", Headers: map[string]string{"Content-Type": "application/json"}},
	}
	p := defaultPayload("api_exposure", signal, field, signal)
	f := r.verifyAndBuild(ctx, "api_exposure", target, p, baseline, rr, signal, false, false, "", "")
	r.recordFinding(ctx, &out, f, "api_exposure", signal)
	return out
}

func apiExposureResponseSurface(endpointURL string, response httpclient.ResponseRecord) bool {
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return false
	}
	contentType := strings.ToLower(response.Headers["Content-Type"])
	body := strings.TrimSpace(response.Body)
	if body == "" || strings.Contains(strings.ToLower(body), "<html") || strings.Contains(strings.ToLower(body), "<!doctype") {
		return false
	}
	if strings.Contains(contentType, "json") || strings.Contains(contentType, "graphql") ||
		strings.Contains(contentType, "problem+") {
		return true
	}
	if strings.HasPrefix(body, "{") || strings.HasPrefix(body, "[") {
		var decoded interface{}
		return json.Unmarshal([]byte(body), &decoded) == nil
	}
	return strings.Contains(strings.ToLower(endpointURL), "/api/")
}

func apiExposureSignal(body string) (signal, field string) {
	for _, match := range secretscan.Detect(body) {
		if secretscan.IsReportable(match) {
			return "server_secret_exposure", match.Kind
		}
	}
	for _, finding := range sensitivedata.Analyze(body) {
		switch finding.Kind {
		case "pii_ssn", "pii_tckn", "pii_iban", "credit_card", "jwt_token", "session_id", "database_dump_leak":
			return "sensitive_data_exposure", finding.Kind
		case "stack_trace", "database_error":
			return "verbose_error_exposure", finding.Kind
		}
	}
	var decoded interface{}
	if json.Unmarshal([]byte(body), &decoded) == nil {
		if key := exposedCredentialField(decoded); key != "" {
			return "sensitive_field_exposure", key
		}
	}
	return "", ""
}

func exposedCredentialField(value interface{}) string {
	switch typed := value.(type) {
	case map[string]interface{}:
		for key, child := range typed {
			normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", "_"), " ", "_"))
			if credentialValueExposed(normalized, child) {
				return normalized
			}
			if nested := exposedCredentialField(child); nested != "" {
				return nested
			}
		}
	case []interface{}:
		for _, child := range typed {
			if nested := exposedCredentialField(child); nested != "" {
				return nested
			}
		}
	}
	return ""
}

func credentialValueExposed(key string, value interface{}) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	text = strings.TrimSpace(text)
	lower := strings.ToLower(text)
	if text == "" || lower == "null" || lower == "none" || lower == "redacted" ||
		strings.Trim(text, "*xX•") == "" {
		return false
	}
	switch key {
	case "password", "passwd", "password_hash", "api_key", "apikey", "client_secret", "private_key", "secret":
		return len(text) >= 4
	case "access_token", "refresh_token", "session_token", "auth_token", "bearer_token":
		return len(text) >= 16
	default:
		return false
	}
}
