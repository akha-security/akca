package modules

import (
	"context"
	"strings"
)

var cstiPayloads = []struct {
	payload   string
	evalToken string
	framework string
}{
	{payload: "{{7777*7777}}", evalToken: "60481729", framework: "AngularJS / Vue.js / Alpine.js (Expression)"},
	{payload: "${7777*7777}", evalToken: "60481729", framework: "ES6 Template / Polymer"},
	{payload: "<%= 7777*7777 %>", evalToken: "60481729", framework: "Underscore / EJS / Lodash"},
}

func (r *Runner) runCSTI(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("csti_detection", target); !ok {
		r.emitSkip("csti_detection", target, reason)
		return nil
	}

	if target.Parameter == "" {
		return nil
	}

	baseline, baselineErr := r.cachedEmptyProbe(ctx, target)
	if baselineErr != nil {
		return nil
	}

	var out []ModuleFinding

	for _, cp := range cstiPayloads {
		if ctx.Err() != nil {
			break
		}

		rr, err := r.probe(ctx, target, cp.payload)
		if err != nil || rr.Response.StatusCode != 200 {
			continue
		}

		body := rr.Response.Body
		// The arithmetic result must appear in the body, but the unrendered template payload string itself must NOT appear literally
		if strings.Contains(body, cp.evalToken) && !strings.Contains(body, cp.payload) && !strings.Contains(baseline.Response.Body, cp.evalToken) {
			r.emitDiscovery("csti_detection", target, "template_arithmetic_observed", "Arithmetic output observed in HTTP response; frontend execution is unproven")
		}
	}

	return append(out, r.runBrowserCSTI(ctx, target, "csti_detection")...)
}

func cstiSignalConfirmed(body, baseline, payload, signal string, probeStatus int) bool {
	if signal != "csti_expression_evaluated" || probeStatus != 200 {
		return false
	}
	if strings.Contains(body, payload) || body == baseline {
		return false
	}
	token := cstiEvalTokenForPayload(payload)
	return token != "" && strings.Contains(body, token) && !strings.Contains(baseline, token)
}

func cstiEvalTokenForPayload(payload string) string {
	switch payload {
	case "{{7777*7777}}", "${7777*7777}", "<%= 7777*7777 %>":
		return "60481729"
	default:
		return ""
	}
}
