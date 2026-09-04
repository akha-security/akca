package modules

import (
	"context"
	"fmt"
	"strings"
)

var jsonpParamNames = []string{"callback", "cb", "jsonp", "jsonpcallback", "func", "_callback", "handler"}

func (r *Runner) runJSONPCallback(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("jsonp_callback", target); !ok {
		r.emitSkip("jsonp_callback", target, reason)
		return nil
	}

	lowerParam := strings.ToLower(target.Parameter)
	isJSONPParam := false
	for _, name := range jsonpParamNames {
		if lowerParam == name {
			isJSONPParam = true
			break
		}
	}
	if !isJSONPParam {
		return nil
	}

	baseline, baselineErr := r.cachedEmptyProbe(ctx, target)
	if baselineErr != nil {
		return nil
	}

	var out []ModuleFinding

	// Test 1: Callback Reflected XSS / Arbitrary Function Injection
	canaryFn := "akca_jsonp_cb_" + randomProbeToken()
	rr, err := r.probe(ctx, target, canaryFn)
	if err != nil || rr.Response.StatusCode != 200 {
		return nil
	}

	body := strings.TrimSpace(rr.Response.Body)
	// Check if body starts with the injected callback wrapper: e.g. akca_jsonp_cb_1234(...)
	if strings.HasPrefix(body, canaryFn+"(") || strings.HasPrefix(body, "/**/"+canaryFn+"(") {
		signal := "jsonp_callback_injection"
		p := defaultPayload("jsonp_callback", signal, canaryFn, signal)
		f := r.verifyAndBuild(ctx, "jsonp_callback", target, p, baseline, rr, signal, false, false, "", "")
		if f != nil {
			f.Severity = "medium"
			f.Title = "JSONP Endpoint Callback Wrapper Injection"
			f.Description = fmt.Sprintf("JSONP endpoint '%s' wraps JSON responses in user-controlled callback function specified by '%s'. If cross-origin credentials (cookies) are supported, this permits Cross-Site Script Inclusion (XSSI) data leakage.", target.EndpointURL, target.Parameter)

			// If sensitive data like email/token/user is present in the JSON payload, bump to High
			lowerBody := strings.ToLower(body)
			if strings.Contains(lowerBody, "email") || strings.Contains(lowerBody, "token") || strings.Contains(lowerBody, "password") || strings.Contains(lowerBody, "user_id") {
				f.Severity = "high"
				f.Description += " Sensitive user fields were detected inside the reflected JSONP payload."
			}
			r.recordFinding(ctx, &out, f, "jsonp_callback", signal)
		}
	}

	return out
}
