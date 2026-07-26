package modules

import (
	"context"
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
	var out []ModuleFinding
	rr, err := r.cachedEmptyProbe(ctx, target)
	if err != nil {
		return nil
	}
	signal, field := apiExposureSignal(rr.Response.Body)
	if signal == "" {
		return nil
	}
	baseline := httpclient.RequestResponse{
		Response: httpclient.ResponseRecord{StatusCode: 200, Body: "{}", Headers: map[string]string{"Content-Type": "application/json"}},
	}
	p := defaultPayload("api_exposure", signal, field, signal)
	f := r.verifyAndBuild(ctx, "api_exposure", target, p, baseline, rr, signal, false, false, "", "")
	r.recordFinding(&out, f, "api_exposure", signal)
	return out
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
