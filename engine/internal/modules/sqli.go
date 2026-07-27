package modules

import (
	"context"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/evidencemarkers"
	"github.com/akha-security/akca/engine/internal/findingtext"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/sensor"
	"github.com/akha-security/akca/engine/internal/timingblind"
	"github.com/akha-security/akca/engine/internal/verification"
)

func (r *Runner) runSQLi(ctx context.Context, target ScanTarget) []ModuleFinding {
	var out []ModuleFinding
	baseline, ok := r.stableNativeBaselineForModule(ctx, "sqli", target)
	if !ok {
		return nil
	}
	sqliPayloads := payloadsForClass(target.Payloads.Payloads, "sqli")
	advancedAllowed := sqliAdvancedSurfaceReady(target, sqliPayloads)
	preflightEvidence := false
	timingBase := r.calibrateTargetTimingForModule(ctx, "sqli", target)
	sleepSec := timingblind.RecommendSleepSec(timingBase)
	dbHint := r.techDatabaseHint(target.EndpointURL)

	for _, p := range sqliPayloads {
		if p.IsNegativeControl || p.IsControl {
			continue
		}
		// Content-difference SQLi must be evaluated as a matched true/false
		// predicate pair. A standalone changed page is indistinguishable from
		// cache, personalization, WAF routing and ordinary application behavior.
		if strings.HasPrefix(strings.ToLower(p.ExpectedSignal), "content_change") ||
			strings.HasPrefix(strings.ToLower(p.ExpectedSignal), "boolean_pair") {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		probePayload := p
		if timingblind.IsTimeDelayPayload(p.Value, p.ExpectedSignal) {
			probePayload.Value = timingblind.RewriteSleepDuration(p.Value, sleepSec)
		}

		var rr httpclient.RequestResponse
		var probeTarget ScanTarget
		var elapsed int64
		var timingSamples []int64
		var zeroSamples []int64

		if timingblind.IsTimeDelayPayload(probePayload.Value, probePayload.ExpectedSignal) {
			ok, delayMs, samples, zeroS := r.sqliTimingVerified(ctx, target, probePayload.Value, dbHint, timingBase, sleepSec)
			if !ok {
				continue
			}
			elapsed = delayMs
			timingSamples = samples
			zeroSamples = zeroS
			attempt, ok := r.sqliBestAttempt(ctx, target, probePayload.Value, baseline.Response.Body)
			if !ok {
				continue
			}
			rr = attempt.RR
			probeTarget = attempt.Target
		} else {
			start := time.Now()
			attempt, ok := r.sqliBestAttempt(ctx, target, probePayload.Value, baseline.Response.Body)
			if !ok {
				continue
			}
			rr = attempt.RR
			probeTarget = attempt.Target
			elapsed = time.Since(start).Milliseconds()
			if rr.Response.Duration.Milliseconds() > 0 {
				elapsed = rr.Response.Duration.Milliseconds()
			}
		}
		if probeTarget.EndpointURL == "" {
			probeTarget = target
		}

		// Skip CDN/infrastructure error responses — they are not evidence of SQLi.
		// However, 500/501 can carry genuine SQL error messages, so only skip them
		// if the body does NOT contain a real SQL error pattern.
		if isInfrastructureError(rr.Response.StatusCode) {
			continue
		}
		if (rr.Response.StatusCode == 500 || rr.Response.StatusCode == 501) &&
			!sqliErrorInBody(rr.Response.Body, baseline.Response.Body) {
			continue
		}
		signal := detectSQLiSignal(probePayload, rr.Response.Body, baseline.Response.Body, elapsed, timingBase, sleepSec, rr.Response.StatusCode)
		runtimeEvent, runtimeAssessment, runtimeObserved := r.runtimeAssessment(ctx, rr)
		if runtimeObserved && runtimeAssessment.Safe {
			// A correlated prepared/bound SQL execution is deterministic safe
			// evidence and overrides response-only SQL error/body heuristics.
			continue
		}
		if runtimeObserved && runtimeAssessment.Vulnerable && runtimeAssessment.Sink != nil &&
			strings.EqualFold(runtimeAssessment.Sink.Type, "sql") {
			f := r.buildSQLiRuntimeFinding(probeTarget, probePayload, baseline, rr, runtimeEvent, runtimeAssessment)
			if f != nil {
				_ = r.persistFinding(*f)
				out = append(out, *f)
			}
			continue
		}
		if signal == "" {
			continue
		}
		if signal == "error_based" {
			preflightEvidence = true
		}
		if !sqliSignalConfirmed(probePayload, rr.Response.Body, baseline.Response.Body, signal) {
			continue
		}
		// Deterministic re-probes to eliminate false positives
		if signal == "error_based" {
			reprobe, err := r.probeForModule(ctx, "sqli", probeTarget, probePayload.Value)
			if err != nil || !sqliErrorInBody(reprobe.Response.Body, baseline.Response.Body) {
				continue
			}
			syntaxControl := sqliSyntaxPreservingControl(probePayload.Value)
			controlRR, controlErr := r.probeForModule(ctx, "sqli", probeTarget, syntaxControl)
			if controlErr != nil || sqliErrorInBody(controlRR.Response.Body, baseline.Response.Body) {
				continue
			}
		}
		if signal == "timing_differential" && timingblind.UseDelayedVerification(r.cfg) {
			r.scheduleDelayedTimingProbe(delayedTimingProbe{
				Target: target, Module: "sqli", Payload: probePayload,
				Baseline: timingBase, SleepSec: sleepSec, FirstMs: elapsed, Scheduled: time.Now(),
			})
			continue
		}
		f := r.buildSQLiFinding(ctx, probeTarget, probePayload, baseline, rr, signal, "", elapsed, timingBase, sleepSec, timingSamples, zeroSamples)
		if f != nil {
			_ = r.persistFinding(*f)
			out = append(out, *f)
		}
	}

	if !advancedAllowed && !preflightEvidence {
		return out
	}

	for _, dyn := range []payloadgen.Payload{
		timingblind.SQLiSleepPayload(sleepSec, dbHint),
		timingblind.SQLiPgSleepPayload(sleepSec),
		timingblind.SQLiBenchmarkPayload(2_500_000 + sleepSec*200_000),
	} {
		if ctx.Err() != nil {
			break
		}
		ok, elapsed, samples, zeroS := r.sqliTimingVerified(ctx, target, dyn.Value, dbHint, timingBase, sleepSec)
		if !ok {
			continue
		}
		if timingblind.UseDelayedVerification(r.cfg) {
			r.scheduleDelayedTimingProbe(delayedTimingProbe{
				Target: target, Module: "sqli", Payload: dyn,
				Baseline: timingBase, SleepSec: sleepSec, FirstMs: elapsed, Scheduled: time.Now(),
			})
			continue
		}
		attempt, ok := r.sqliBestAttempt(ctx, target, dyn.Value, baseline.Response.Body)
		if !ok {
			continue
		}
		probeTarget := attempt.Target
		if probeTarget.EndpointURL == "" {
			probeTarget = target
		}
		f := r.buildSQLiFinding(ctx, probeTarget, dyn, baseline, attempt.RR, "timing_differential", "", elapsed, timingBase, sleepSec, samples, zeroS)
		if f != nil {
			_ = r.persistFinding(*f)
			out = append(out, *f)
		}
	}

	out = append(out, r.booleanBlindSQLiProbe(ctx, target, baseline)...)
	out = append(out, r.unionSQLiProbe(ctx, target, baseline)...)
	out = append(out, r.stackedSQLiProbe(ctx, target, baseline, timingBase, sleepSec, dbHint)...)
	out = append(out, r.runSQLiOOB(ctx, target, baseline)...)
	return out
}

func (r *Runner) buildSQLiRuntimeFinding(target ScanTarget, p payloadgen.Payload,
	baseline, probe httpclient.RequestResponse, event sensor.Event, assessment sensor.Assessment) *ModuleFinding {
	if assessment.Sink == nil || event.TraceID == "" || event.RequestID == "" {
		return nil
	}
	sinkName := strings.ToLower(strings.TrimSpace(assessment.Sink.Type)) + ":" +
		strings.TrimSpace(assessment.Sink.Operation)
	candidate := verification.Candidate{
		ScanID: r.scanID, Title: "sqli on " + target.Parameter, VulnClass: "sqli",
		EndpointURL: target.EndpointURL, Method: target.Method, Parameter: target.Parameter,
		Payload: p.Value, Module: "sqli", Signal: "runtime_unsafe_sql_sink",
		Baseline: snapshot(baseline.Response), Probe: snapshot(probe.Response),
		Reflection: &target.Profile, DirectTypedSignal: true,
		ProofPolicyVersion: verification.CurrentProofPolicyVersion,
		RequestedProofType: verification.ProofRuntimeTrace,
	}
	candidate.Observations = append(candidate.Observations,
		r.observation("sqli", target, verification.RoleNativeBaseline, 1, baseline),
		r.observation("sqli", target, verification.RolePositiveProbe, 1, probe),
		verification.NewRuntimeObservation(
			r.scanID, "sqli", target.EndpointURL, target.Parameter, target.Location,
			event.RequestID, event.TraceID, sinkName, 1, false,
		),
	)
	result := r.verifier.Verify(candidate)
	if result.Suppressed || !result.ProofSatisfied {
		return nil
	}
	return &ModuleFinding{
		Title: findingtext.HumanTitle("sqli"), VulnClass: "sqli",
		Severity: severityFor("sqli", result.Confidence), Endpoint: target.EndpointURL,
		Parameter: target.Parameter, Location: target.Location, Confidence: result.Confidence,
		Description: findingtext.HumanDescription(
			"sqli", "runtime_unsafe_sql_sink", target.Parameter, target.EndpointURL, p.Value, p.Variant, target.Location,
		),
		Evidence: Evidence{
			Module: "sqli", Signal: "runtime_unsafe_sql_sink", Payload: p,
			Parameter: target.Parameter, Location: target.Location,
			ResponseMarkers: []string{"correlated runtime trace", sinkName},
			Request:         probe.Request, Response: probe.Response, Verification: result,
			DetectedAt: time.Now().UTC(),
		},
	}
}

func sqliAdvancedSurfaceReady(target ScanTarget, payloads []payloadgen.Payload) bool {
	if strings.TrimSpace(target.Parameter) == "" {
		return false
	}
	location := strings.ToLower(strings.TrimSpace(target.Location))
	if location == "" {
		location = strings.ToLower(strings.TrimSpace(target.Profile.ParameterLocation))
	}
	name := strings.ToLower(strings.TrimSpace(target.Parameter))
	if location == "header" {
		// Header-backed SQLi is real (for example in audit/logging pipelines),
		// so do not skip User-Agent, X-Forwarded-* or custom headers. False
		// positives are controlled by the strict boolean/error/timing/OAST proof
		// contracts rather than by suppressing the probe surface.
		return true
	}
	// Generated payload persistence is an optimization input, not a coverage
	// precondition. Dynamic boolean/time/stacked probes are built by this
	// runner and must still execute when payload generation was unavailable or
	// filtered by learning.
	_ = payloads
	return sqliSemanticParameterName(name)
}

func sqliSemanticParameterName(name string) bool {
	canonical := strings.NewReplacer("-", "_", ".", "_", "[", "_", "]", "_").Replace(
		strings.ToLower(strings.TrimSpace(name)),
	)
	parts := strings.FieldsFunc(canonical, func(r rune) bool {
		return r == '_' || r == ':' || r == '/'
	})
	for _, part := range parts {
		switch part {
		case "id", "uid", "user", "username", "email", "q", "query", "search",
			"term", "keyword", "filter", "where", "category", "product",
			"account", "order", "item", "sort":
			return true
		}
		for _, suffix := range []string{"id", "query", "filter"} {
			if len(part) > len(suffix)+2 && strings.HasSuffix(part, suffix) {
				return true
			}
		}
	}
	return false
}

func (r *Runner) buildSQLiFinding(ctx context.Context, target ScanTarget, p payloadgen.Payload, baseline, probe httpclient.RequestResponse,
	signal, oastURL string, elapsed int64, timingBase timingblind.Baseline, sleepSec int, timingSamples []int64, zeroSamples []int64) *ModuleFinding {
	if !sqliFindingAllowed(p, signal, baseline.Response, probe.Response, oastURL) {
		return nil
	}
	candidate := r.buildCandidate(ctx, "sqli", target, p, baseline, probe, signal)
	if signal == "timing_differential" || signal == "stacked_timing" {
		candidate.TimingBaseline = append([]int64(nil), timingBase.Samples...)
		if len(timingSamples) > 0 {
			candidate.TimingSamples = timingSamples
			candidate.TimingMatchedControl = append([]int64(nil), zeroSamples...)
			candidate.TimingControl = append([]int64(nil), zeroSamples...)
		} else {
			candidate.TimingSamples = []int64{elapsed}
			candidate.TimingControl = append([]int64(nil), timingBase.Samples...)
		}
	}
	result := r.verifier.Verify(candidate)
	if result.Suppressed {
		return nil
	}
	if signal == "error_based" && result.Confidence == verification.Confirmed {
		result.Confidence = verification.HighConfidence
		if result.Score >= 0.9 {
			result.Score = 0.89
		}
	}
	return &ModuleFinding{
		Title:       findingtext.HumanTitle("sqli"),
		VulnClass:   "sqli",
		Severity:    severityFor("sqli", result.Confidence),
		Endpoint:    target.EndpointURL,
		Parameter:   target.Parameter,
		Location:    target.Location,
		Description: findingtext.HumanDescription("sqli", signal, target.Parameter, target.EndpointURL, p.Value, p.Variant, target.Location),
		Confidence:  result.Confidence,
		Evidence: Evidence{
			Module: "sqli", Signal: signal, Payload: p,
			Parameter: target.Parameter, Location: target.Location,
			ResponseMarkers: evidencemarkers.ForResponse(
				p.Value, signal, baseline.Response.Body, probe.Response.Body, "",
			),
			Request: probe.Request, Response: probe.Response, Verification: result, OASTURL: oastURL,
			DetectedAt: time.Now().UTC(),
		},
	}
}

func sqliSyntaxPreservingControl(value string) string {
	if strings.TrimSpace(value) == "'" {
		return "''"
	}
	if strings.TrimSpace(value) == `"` {
		return `""`
	}
	control := strings.NewReplacer(
		"SELECT", "SELXCT", "select", "selxct",
		"UNION", "UNXON", "union", "unxon",
		"ORDER", "ORDEX", "order", "ordex",
		"WHERE", "WHXRE", "where", "whxre",
		" AND ", " XND ", " and ", " xnd ",
		" OR ", " XR ", " or ", " xr ",
	).Replace(value)
	if control == value {
		return value + value
	}
	return control
}

func detectSQLiSignal(p payloadgen.Payload, body, baseline string, elapsedMs int64, timingBase timingblind.Baseline, sleepSec int, probeStatus int) string {
	// CDN/infrastructure errors (e.g. Cloudflare 520-527, 502, 503, 504) are
	// never valid evidence of SQL injection. Their error pages cause body diffs
	// and their timeouts mimic sleep-based injections.
	if isInfrastructureError(probeStatus) {
		return ""
	}
	if sqliErrorInBody(body, baseline) {
		return "error_based"
	}
	if strings.HasPrefix(p.ExpectedSignal, "sql_error") {
		if sqliErrorInBody(body, baseline) {
			return "error_based"
		}
	}
	// A body difference from one predicate is not SQL execution evidence.
	// Boolean SQLi is emitted only by booleanBlindSQLiProbe after matched,
	// alternating true/false probes reproduce on the same request surface.
	if strings.HasPrefix(p.ExpectedSignal, "timing") || timingblind.IsTimeDelayPayload(p.Value, p.ExpectedSignal) {
		if ok, _ := timingblind.VerifyProbe(elapsedMs, timingBase, sleepSec); ok {
			return "timing_differential"
		}
	}
	return ""
}

func isTimeBasedSQLi(p payloadgen.Payload) bool {
	return timingblind.IsTimeDelayPayload(p.Value, p.ExpectedSignal)
}
