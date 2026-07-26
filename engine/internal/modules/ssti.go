package modules

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/sstibypass"
)

var sstiMathRe = regexp.MustCompile(`(\d{1,7})\s*\*\s*(\d{1,7})`)

func baseSSTIProbes() []payloadgen.Payload {
	// Use uncommon products (143, 221) to avoid false positives from "49" in page content.
	return []payloadgen.Payload{
		{Value: `{{11*13}}`, VulnClass: "ssti", Variant: "twig", ExpectedSignal: "template_evaluation"},
		{Value: `${13*17}`, VulnClass: "ssti", Variant: "jinja", ExpectedSignal: "template_evaluation"},
		{Value: `<%= 11*13 %>`, VulnClass: "ssti", Variant: "erb", ExpectedSignal: "template_evaluation"},
	}
}

func mergeSSTIProbes(parts ...[]payloadgen.Payload) []payloadgen.Payload {
	seen := map[string]struct{}{}
	var out []payloadgen.Payload
	for _, list := range parts {
		for _, p := range list {
			if p.Value == "" {
				continue
			}
			if _, ok := seen[p.Value]; ok {
				continue
			}
			seen[p.Value] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

func (r *Runner) runSSTI(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("ssti", target); !ok {
		r.emitSkip("ssti", target, reason)
		return nil
	}
	var out []ModuleFinding
	baseline, ok := r.stableNativeBaseline(ctx, target)
	if !ok {
		return nil
	}
	probes := mergeSSTIProbes(
		baseSSTIProbes(),
		payloadsForClass(target.Payloads.Payloads, "ssti"),
		sstibypass.EsotericPayloads(target.Payloads.Tech),
	)
	for _, p := range probes {
		attempts := r.injectionProbeAttempts(ctx, target, p.Value)
		attempt := pickBodyDiffAttempt(attempts, baseline.Response.Body)
		if len(attempts) == 0 {
			continue
		}
		rr := attempt.RR
		if isInfrastructureError(rr.Response.StatusCode) || (rr.Response.StatusCode >= 400 && baseline.Response.StatusCode < 400) {
			continue
		}
		probeTarget := attempt.Target
		if probeTarget.EndpointURL == "" {
			probeTarget = target
		}
		if runtimeFinding, handled := r.runtimeSinkProof(ctx, "ssti", probeTarget, p, baseline, rr); handled {
			if runtimeFinding != nil {
				r.recordFinding(&out, runtimeFinding, "ssti", runtimeFinding.Evidence.Signal)
				return out
			}
			continue
		}
		signal := detectSSTISignal(p, rr.Response.Body, baseline.Response.Body)
		if signal == "" {
			signal = sstibypass.Analyze(p, rr.Response.Body, baseline.Response.Body)
		}
		if signal == "" {
			continue
		}
		// Parser errors and generic operating-system strings are useful
		// telemetry, but are not execution proof.
		if signal == "error_trace" || signal == "command_output" || signal == "separator_output" ||
			signal == "string_multiply_eval" {
			continue
		}
		if !sstiSignalConfirmed(p, rr.Response.Body, baseline.Response.Body, signal) {
			continue
		}
		// Double-verification: re-probe with same payload and confirm result is deterministic.
		if signal == "math_evaluation" || signal == "template_evaluation_49" {
			if !r.sstiTemplateOnlyEvaluation(ctx, probeTarget, p, baseline.Response.Body) {
				continue
			}
			control, ok := pairedSSTIPayload(p)
			if !ok {
				continue
			}
			reprobe, repErr := r.probe(ctx, probeTarget, control.Value)
			if repErr != nil || reprobe.Response.StatusCode != rr.Response.StatusCode ||
				!sstiSignalConfirmed(control, reprobe.Response.Body, baseline.Response.Body, signal) ||
				normalizeVolatileFields(reprobe.Response.Body) == normalizeVolatileFields(rr.Response.Body) {
				continue
			}
		}
		f := r.verifyAndBuild(ctx, "ssti", probeTarget, p, baseline, rr, signal, false, false, "", "")
		if f != nil {
			_ = r.persistFinding(*f)
			out = append(out, *f)
		}
	}
	return out
}

func (r *Runner) sstiTemplateOnlyEvaluation(ctx context.Context, target ScanTarget, p payloadgen.Payload, baseline string) bool {
	m := sstiMathRe.FindStringSubmatch(p.Value)
	if m == nil {
		return false
	}
	a, errA := strconv.Atoi(m[1])
	b, errB := strconv.Atoi(m[2])
	if errA != nil || errB != nil {
		return false
	}
	expected := strconv.Itoa(a * b)
	raw := m[1] + "*" + m[2]
	malformed := malformedSSTIPayload(p.Value)
	for _, control := range []string{raw, malformed} {
		if control == "" || control == p.Value {
			return false
		}
		rr, err := r.probe(ctx, target, control)
		if err != nil {
			return false
		}
		if containsStandaloneDigits(rr.Response.Body, expected) &&
			!containsStandaloneDigits(baseline, expected) {
			return false
		}
	}
	return true
}

func malformedSSTIPayload(value string) string {
	switch {
	case strings.HasPrefix(value, "{{") && strings.HasSuffix(value, "}}"):
		return strings.TrimSuffix(value, "}}")
	case strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}"):
		return strings.TrimSuffix(value, "}")
	case strings.HasPrefix(value, "<%=") && strings.HasSuffix(value, "%>"):
		return strings.TrimSuffix(value, "%>")
	default:
		return value + "{"
	}
}

func pairedSSTIPayload(p payloadgen.Payload) (payloadgen.Payload, bool) {
	m := sstiMathRe.FindStringSubmatchIndex(p.Value)
	if m == nil {
		return payloadgen.Payload{}, false
	}
	a, errA := strconv.Atoi(p.Value[m[2]:m[3]])
	b, errB := strconv.Atoi(p.Value[m[4]:m[5]])
	if errA != nil || errB != nil || a < 2 || b < 2 {
		return payloadgen.Payload{}, false
	}
	replacement := strconv.Itoa(a+2) + "*" + strconv.Itoa(b+4)
	control := p
	control.Value = p.Value[:m[0]] + replacement + p.Value[m[1]:]
	control.Variant = p.Variant + "_paired_control"
	return control, true
}

func detectSSTISignal(p payloadgen.Payload, body, baseline string) string {
	if strings.Contains(body, p.Value) && !strings.Contains(baseline, p.Value) {
		return ""
	}
	if m := sstiMathRe.FindStringSubmatch(p.Value); m != nil {
		a, errA := strconv.Atoi(m[1])
		b, errB := strconv.Atoi(m[2])
		if errA == nil && errB == nil && a > 1 && b > 1 {
			want := strconv.Itoa(a * b)
			if len(want) >= 3 && strings.Contains(body, want) && !strings.Contains(baseline, want) {
				return "math_evaluation"
			}
		}
	}
	if sstiErrorTraceRe.MatchString(body) && !sstiErrorTraceRe.MatchString(baseline) {
		return "error_trace"
	}
	return ""
}
