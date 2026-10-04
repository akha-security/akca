package modules

import (
	"context"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/verification"
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
			var replays []httpclient.RequestResponse
			for i := 0; i < 2; i++ {
				replay, replayErr := r.probe(ctx, target, cp.payload)
				if replayErr != nil || !cstiSignalConfirmed(replay.Response.Body, baseline.Response.Body, cp.payload, "csti_expression_evaluated", replay.Response.StatusCode) {
					replays = nil
					break
				}
				replays = append(replays, replay)
			}
			controlPayload := strings.Replace(cp.payload, "7777*7777", "7777+7777", 1)
			control, controlErr := r.probe(ctx, target, controlPayload)
			if len(replays) == 2 && controlErr == nil && !strings.Contains(control.Response.Body, cp.evalToken) {
				p := defaultPayload("csti_detection", cp.framework, cp.payload, "csti_expression_evaluated")
				f := r.verifyAndBuildWithCandidate(ctx, "csti_detection", target, p, baseline, rr,
					"csti_expression_evaluated", false, false, "", "", func(c *verification.Candidate) {
						c.RequestedProofType = verification.ProofDifferentialReplay
						c.NegativeControlSet, c.NegativeControlOK = true, true
						c.TypedReplayHits = []bool{true, true, true}
						c.Observations = append(c.Observations,
							r.observation("csti_detection", target, verification.RolePositiveReplay, 2, replays[0]),
							r.observation("csti_detection", target, verification.RolePositiveReplay, 3, replays[1]),
							r.observation("csti_detection", target, verification.RoleNegativeControl, 1, control))
					})
				if f != nil {
					f.Title = "Template expression injection (arithmetic execution confirmed)"
					f.Severity = "high"
					f.Description = "A unique arithmetic template expression was evaluated consistently while a paired syntax control did not produce the same result. Browser-side versus server-side execution is not inferred from the HTTP response alone."
					r.recordFinding(ctx, &out, f, "csti_detection", "csti_expression_evaluated")
				}
			}
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
