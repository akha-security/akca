package modules

import (
	"context"
	"fmt"
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
	{payload: "{{constructor.constructor('alert(1)')()}}", evalToken: "alert(1)", framework: "AngularJS Sandbox Escape"},
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
			signal := "csti_expression_evaluated"
			p := defaultPayload("csti_detection", signal, cp.payload, signal)
			f := r.verifyAndBuild(ctx, "csti_detection", target, p, baseline, rr, signal, false, false, "", "")
			if f != nil {
				f.Severity = "high"
				f.Title = fmt.Sprintf("Client-Side Template Injection (CSTI - %s)", cp.framework)
				f.Description = fmt.Sprintf("Client-side template expression '%s' injected into parameter '%s' was evaluated to '%s' by the frontend framework.", cp.payload, target.Parameter, cp.evalToken)
				r.recordFinding(ctx, &out, f, "csti_detection", signal)
				return out
			}
		}
	}

	return out
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
	case "{{constructor.constructor('alert(1)')()}}":
		return "alert(1)"
	default:
		return ""
	}
}
