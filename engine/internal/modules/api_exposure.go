package modules

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

var sensitiveFieldPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)"password"\s*:\s*"[^"]+"`),
	regexp.MustCompile(`(?i)"ssn"\s*:\s*"[^"]+"`),
	regexp.MustCompile(`(?i)"credit_?card"\s*:\s*"[^"]+"`),
	regexp.MustCompile(`(?i)"api_?key"\s*:\s*"[^"]+"`),
	regexp.MustCompile(`(?i)"secret"\s*:\s*"[^"]+"`),
	regexp.MustCompile(`(?i)"token"\s*:\s*"[^"]+"`),
}

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
	for _, re := range sensitiveFieldPatterns {
		if m := re.FindString(body); m != "" {
			return "sensitive_field_exposure", m
		}
	}
	lower := strings.ToLower(body)
	if strings.Contains(lower, "stack trace") || strings.Contains(lower, "sql syntax") {
		return "verbose_error_exposure", "error_detail"
	}
	if strings.Contains(lower, `"internal_id"`) || strings.Contains(lower, `"employee_id"`) {
		return "internal_id_exposure", "internal_id"
	}
	return "", ""
}
