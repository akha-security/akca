package modules

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/evidencemarkers"
	"github.com/akha-security/akca/engine/internal/findingtext"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/learning"
	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/reflection"
	"github.com/akha-security/akca/engine/internal/verification"
)

func (r *Runner) probe(ctx context.Context, target ScanTarget, payload string) (httpclient.RequestResponse, error) {
	method := strings.ToUpper(target.Method)
	if method == "" {
		method = http.MethodGet
	}
	loc := target.Location
	if loc == "" {
		loc = target.Profile.ParameterLocation
	}
	probeURL, body, headers, err := reflection.BuildProbeRequestWithTemplate(
		target.EndpointURL, method, target.Parameter, loc, payload, target.BodyTemplate,
	)
	if err != nil {
		return httpclient.RequestResponse{}, err
	}
	headers = mergeHeaders(headers, r.wafHeaders(target.EndpointURL))
	effMethod := effectiveMethod(method, loc)
	headers = sanitizeProbeHeaders(effMethod, body, headers)
	headers = r.registerRuntimeProbe(target, payload, headers)
	return r.client.Do(ctx, effMethod, probeURL, body, headers)
}

func sanitizeProbeHeaders(method string, body []byte, headers map[string]string) map[string]string {
	if len(headers) == 0 || len(body) > 0 {
		return headers
	}
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodDelete, http.MethodOptions:
	default:
		return headers
	}
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		if strings.EqualFold(k, "Transfer-Encoding") || strings.EqualFold(k, "Content-Type") {
			continue
		}
		out[k] = v
	}
	return out
}

// effectiveMethod upgrades GET to POST when the injection surface is a body
// (form, JSON, XML) since those payloads cannot be delivered via query string.
func effectiveMethod(method, location string) string {
	return reflection.EffectiveMethod(method, location)
}

func injectParameter(endpointURL, param, value string) (string, error) {
	rawURL, _, _, err := reflection.BuildProbeRequest(endpointURL, http.MethodGet, param, "query", value)
	return rawURL, err
}

func payloadsForClass(payloads []payloadgen.Payload, vulnClass string) []payloadgen.Payload {
	var out []payloadgen.Payload
	for _, p := range payloads {
		if p.VulnClass == vulnClass {
			out = append(out, p)
		}
	}
	return out
}

func snapshot(rr httpclient.ResponseRecord) verification.ResponseSnapshot {
	ct := ""
	for k, v := range rr.Headers {
		if strings.EqualFold(k, "Content-Type") {
			ct = v
			break
		}
	}
	return verification.ResponseSnapshot{
		StatusCode: rr.StatusCode, Body: rr.Body, Headers: rr.Headers,
		DurationMs: rr.Duration.Milliseconds(), ContentType: ct,
	}
}

// baseSeverity is the intrinsic severity of a vulnerability class assuming the
// finding is real (high confidence).
func baseSeverity(module string) string {
	switch module {
	case "api_versioning":
		return "info"
	case "sqli", "command_injection", "ssti", "xxe", "ssrf", "deserialization", "lfi", "rce", "nosql":
		return "critical"
	case "xss", "blind_xss", "idor", "auth_bypass", "open_redirect", "file_upload":
		return "high"
	default:
		return "medium"
	}
}

var severityRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// capSeverity clamps sev so it never exceeds max.
func capSeverity(sev, max string) string {
	if severityRank[sev] <= severityRank[max] {
		return sev
	}
	return max
}

// severityFor reports a severity that honours BOTH the vulnerability class and
// how confident the engine is. A command injection we only *suspect*
// (NeedsManualReview / Potential) is no longer blindly reported as "high" — it
// is capped so the operator can trust high-severity findings and scrutinise the
// lower-confidence ones for false positives.
func severityFor(module string, conf verification.ConfidenceLevel) string {
	base := baseSeverity(module)
	switch module {
	case "security_headers", "tls_misconfig", "rate_limit", "api_exposure", "api_versioning":
		base = capSeverity(base, "low")
	}
	switch conf {
	case verification.Confirmed, verification.HighConfidence:
		return base
	case verification.Potential:
		// SSRF and LFI only reach finding construction after their typed
		// evidence guards confirm a class-specific response marker (metadata,
		// passwd/win.ini content, etc.). Keep confidence visible separately,
		// but do not mislabel the impact of an accepted server-side data access
		// primitive as Medium. OAST/high-confidence confirmation remains
		// Critical via the branch above.
		if module == "ssrf" || module == "lfi" {
			return capSeverity(base, "high")
		}
		return capSeverity(base, "medium")
	default: // NeedsManualReview / anything weaker
		return capSeverity(base, "low")
	}
}

func isPendingOASTSignal(signal, oastURL string) bool {
	if !isValidOASTURL(oastURL) {
		return false
	}
	lower := strings.ToLower(signal)
	return strings.Contains(lower, "oast") || strings.HasPrefix(lower, "oob_")
}

func (r *Runner) verifyAndBuild(ctx context.Context, module string, target ScanTarget, p payloadgen.Payload,
	baseline, probe httpclient.RequestResponse, signal string, domPresent, domExecuted bool, oastURL, storedMarker string) *ModuleFinding {
	return r.verifyAndBuildWithCandidate(ctx, module, target, p, baseline, probe, signal,
		domPresent, domExecuted, oastURL, storedMarker, nil)
}

func (r *Runner) verifyAndBuildWithCandidate(ctx context.Context, module string, target ScanTarget, p payloadgen.Payload,
	baseline, probe httpclient.RequestResponse, signal string, domPresent, domExecuted bool, oastURL, storedMarker string,
	mutate func(*verification.Candidate)) *ModuleFinding {
	if !moduleSignalConfirmed(module, p, signal, baseline.Response, probe.Response, domExecuted, oastURL) {
		return nil
	}
	if isPendingOASTSignal(signal, oastURL) {
		return nil
	}
	baseSnap := snapshot(baseline.Response)
	probeSnap := snapshot(probe.Response)
	candidate := r.buildCandidate(ctx, module, target, p, baseline, probe, signal)
	candidate.Title = module + " on " + target.Parameter
	candidate.DOMPresent = domPresent
	candidate.DOMExecuted = domExecuted
	if domExecuted {
		candidate.Observations = append(candidate.Observations,
			r.observation(module, target, verification.RoleDOMExecution, 1, probe))
	}
	candidate.Baseline = baseSnap
	candidate.Probe = probeSnap
	if mutate != nil {
		mutate(&candidate)
	}
	result := r.verifier.Verify(candidate)
	if result.Suppressed {
		r.recordVerificationOutcome(target.EndpointURL, module, result)
		return nil
	}
	confStr := string(result.Confidence)
	if shouldSuppressLowConfidence(module, signal, result.Score, confStr) {
		if !domExecuted {
			r.recordLearning(target.EndpointURL, module, learning.OutcomeFalsePositive)
			return nil
		}
	}
	if result.Confidence == verification.NeedsManualReview {
		return nil
	}
	if result.Confidence == verification.Potential && (module == "sqli" || module == "ssti" || module == "command_injection") {
		// Only allow Potential findings through if there is strong direct evidence.
		hasDirectEvidence := domExecuted ||
			signal == "error_based" ||
			signal == "error_trace" ||
			signal == "command_output" ||
			signal == "separator_output" ||
			signal == "canary_output" ||
			signal == "math_evaluation" ||
			signal == "delayed_timing_confirmed" ||
			signal == "boolean_pair_confirmed" ||
			signal == "union_signal" ||
			signal == "timing_differential" ||
			signal == "stacked_timing"
		if !hasDirectEvidence {
			return nil
		}
	}
	return &ModuleFinding{
		Title:       findingtext.HumanTitle(module),
		VulnClass:   module,
		Severity:    severityFor(module, result.Confidence),
		Description: findingtext.HumanDescription(module, signal, target.Parameter, target.EndpointURL, p.Value, p.Variant, target.Location),
		Endpoint:    target.EndpointURL,
		Parameter:   target.Parameter,
		Location:    target.Location,
		Confidence:  result.Confidence,
		Evidence: Evidence{
			Module: module, Signal: signal, Payload: p,
			Parameter: target.Parameter, Location: target.Location,
			ResponseMarkers: evidencemarkers.ForResponse(
				p.Value, signal, baseline.Response.Body, probe.Response.Body, storedMarker,
			),
			Request: probe.Request, Response: probe.Response,
			Verification: result, OASTURL: oastURL, StoredMarker: storedMarker,
			ReplayPlan: buildReplayPlan(module, target, baseline, probe, result.Observations),
			DetectedAt: time.Now().UTC(),
		},
	}
}

func buildReplayPlan(module string, target ScanTarget, baseline, probe httpclient.RequestResponse,
	observations []verification.Observation) []ReplayStep {
	makeStep := func(role verification.ObservationRole, rr httpclient.RequestResponse) ReplayStep {
		identityID := ""
		expectedHash := verification.NewHTTPObservation(
			"replay-plan", module, target.EndpointURL, target.Parameter, target.Location,
			role, 1, "", rr.Request.Method, rr.Request.URL, rr.Request.Body, rr.Request.Headers,
			snapshot(rr.Response),
		).NormalizedHash
		for _, observation := range observations {
			if observation.Role == role && strings.EqualFold(observation.RequestMethod, rr.Request.Method) &&
				observation.RequestURL == rr.Request.URL {
				identityID = observation.IdentityID
				if observation.NormalizedHash != "" {
					expectedHash = observation.NormalizedHash
				}
				break
			}
		}
		return ReplayStep{
			Role: role, IdentityID: identityID, Request: rr.Request,
			ExpectedNormalizedHash: expectedHash,
		}
	}
	return []ReplayStep{
		makeStep(verification.RoleNativeBaseline, baseline),
		makeStep(verification.RolePositiveProbe, probe),
	}
}

func (r *Runner) recordVerificationOutcome(endpointURL, module string, result verification.Result) {
	outcome := learning.OutcomeFalsePositive
	for _, reason := range result.DowngradeReasons {
		switch reason {
		case verification.ReasonWAFBlockPage:
			outcome = learning.OutcomeWAFBlocked
		case verification.ReasonUnstableResponse:
			if outcome != learning.OutcomeWAFBlocked {
				outcome = learning.OutcomeUnstable
			}
		}
	}
	r.recordLearning(endpointURL, module, outcome)
}

func buildCandidate(scanID, module string, target ScanTarget, p payloadgen.Payload,
	baseline, probe httpclient.RequestResponse) verification.Candidate {
	return verification.Candidate{
		ScanID: scanID, Title: module + " on " + target.Parameter, VulnClass: module,
		EndpointURL: target.EndpointURL, Method: target.Method, Parameter: target.Parameter,
		Payload: p.Value, Module: module,
		Baseline: snapshot(baseline.Response), Probe: snapshot(probe.Response),
		Reflection: &target.Profile,
	}
}

func (r *Runner) emitFindingDetected(f ModuleFinding, module, signal string, findingID int64) {
	if r.emit == nil {
		return
	}
	conf := f.Evidence.Verification.Score
	if conf <= 0 {
		conf = confidenceScore(f.Confidence)
	}
	if conf > 1 {
		conf = 1
	}
	_ = r.emit("finding_detected", f.Title, map[string]interface{}{
		"finding_id": findingID,
		"module":     module, "signal": signal,
		"title": f.Title, "severity": strings.ToLower(f.Severity),
		"endpoint": f.Endpoint, "endpoint_url": f.Endpoint,
		"vuln_class": f.VulnClass, "confidence": string(f.Confidence),
		"score":                conf,
		"method":               f.Evidence.Request.Method,
		"payload_str":          f.Evidence.Payload.Value,
		"parameter":            f.Parameter,
		"location":             f.Location,
		"response_status":      f.Evidence.Response.StatusCode,
		"response_duration_ms": f.Evidence.Response.Duration.Milliseconds(),
		"timing_confirmed":     f.Evidence.Verification.TimingConfirmed,
		"oast_confirmed":       f.Evidence.Verification.OASTConfirmed,
		"stability_ratio":      f.Evidence.Verification.StabilityRatio,
		"typed_replay_ratio":   f.Evidence.Verification.TypedReplayRatio,
		"negative_control_ok":  f.Evidence.Verification.NegativeControlOK,
	})
}

func repeatSnapshot(s verification.ResponseSnapshot, n int) []verification.ResponseSnapshot {
	out := make([]verification.ResponseSnapshot, n)
	for i := range out {
		out[i] = s
	}
	return out
}
