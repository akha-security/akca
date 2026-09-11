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

		r.emitDiscovery("jsonp_callback", target, "jsonp_callback_wrapper", "JSONP wrapper observed; private browser-readable data requires independent proof")
		f := r.proveCrossOriginRead(ctx, "jsonp_callback", target, "jsonp", canaryFn, baseline, rr)
		if f != nil {
			f.Severity = "high"
			f.Title = "Cross-Origin JSONP Private Data Disclosure"
			f.Description = fmt.Sprintf("Browser script at an opaque origin read the configured private canary from %s in two authenticated sessions; an anonymous browser control did not expose it.", target.EndpointURL)
			r.recordFinding(ctx, &out, f, "jsonp_callback", "browser_private_read")
		}

	}

	return out
}
