package modules

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/verification"
)

func (r *Runner) probePayload(ctx context.Context, target ScanTarget, p payloadgen.Payload) (httpclient.RequestResponse, error) {
	switch p.VulnClass {
	case "xxe":
		if carrier, ok := xxeCarrierFromEncoding(p.Encoding); ok {
			body, contentType, err := buildXXECarrierRequest(carrier, target, p, false, "")
			if err != nil {
				return httpclient.RequestResponse{}, err
			}
			return r.probeWithRawBodyForModule(ctx, "xxe", target, body, contentType, nil)
		}
		ct := "application/xml"
		if p.ExpectedSignal == "soap_xxe" {
			ct = "text/xml"
		}
		return r.probeWithBody(ctx, target, p.Value, ct, nil)
	default:
		return r.probe(ctx, target, p.Value)
	}
}

func (r *Runner) enrichVerification(ctx context.Context, module string, target ScanTarget, p payloadgen.Payload,
	baseline, probe httpclient.RequestResponse, signal string, candidate verification.Candidate) verification.Candidate {
	if module == "xss" && signal == "dom_execution" {
		// Browser execution is an independent proof path. Replaying the DOM
		// canary as a response-regex probe would discard a real execution event
		// because the execution marker is observed in the rendered DOM, not
		// necessarily in the raw HTTP response.
		return candidate
	}
	if usesModuleManagedProof(module) {
		// Identity, state, policy and browser proofs have their own explicit
		// controls. Replaying the last recorded request through the shared
		// session would destroy role isolation and can also observe state only
		// after cleanup, incorrectly suppressing a valid proof.
		return candidate
	}
	lowBudget := r.cfg.PayloadBudget == config.PayloadBudgetLow
	if strings.Contains(strings.ToLower(signal), "timing") {
		// Timing evidence has its own paired control and statistical replay path.
		// Replaying it as a body-difference probe would both waste time and turn
		// the negative control into another artificial delay signal.
		return candidate
	}
	if !(module == "sqli" && signal == "boolean_pair_confirmed") {
		controlPayload := negativeControlPayload(module, target, p)
		controlRR, controlSet, controlErr := r.replayControl(ctx, module, target, p, controlPayload, probe)
		if controlSet && controlErr == nil {
			candidate.Observations = append(candidate.Observations,
				r.observation(module, target, verification.RoleNegativeControl, 1, controlRR))
		}
		if controlSet && controlErr == nil && usableNegativeControl(baseline.Response, controlRR.Response) {
			candidate.NegativeControlSet = true
			candidate.NegativeControlOK = !moduleSignalConfirmed(module, controlPayload, signal,
				baseline.Response, controlRR.Response, false, "")
		}
	}
	if !lowBudget && supportsPolymorphicReplay(module, signal) {
		variants := verification.PolymorphicVariants(module, p.Value)
		hits := make([]bool, 0, len(variants))
		for _, variant := range variants {
			variantPayload := p
			variantPayload.Value = variant
			rr, err := r.probePayload(ctx, target, variantPayload)
			if err != nil {
				hits = append(hits, false)
				continue
			}
			hits = append(hits, moduleSignalConfirmed(module, variantPayload, signal,
				baseline.Response, rr.Response, false, ""))
		}
		if len(hits) >= 2 {
			candidate.PolymorphicHits = hits
		}
	}

	stability := make([]verification.ResponseSnapshot, 0, 3)
	// The original probe already passed the same typed signal guard before
	// reaching this function. Count it as the first observation and make two
	// independent replays, for three observations without wasting a request.
	stability = append(stability, snapshot(probe.Response))
	typedHits := []bool{true}
	for i := 0; i < 2; i++ {
		if ctx.Err() != nil {
			break
		}
		rr, replayable, err := r.replayCandidate(ctx, module, target, p, probe)
		if !replayable {
			return candidate
		}
		if err != nil {
			typedHits = append(typedHits, false)
			continue
		}
		stability = append(stability, snapshot(rr.Response))
		candidate.Observations = append(candidate.Observations,
			r.observation(module, target, verification.RolePositiveReplay, i+2, rr))
		typedHits = append(typedHits, moduleSignalConfirmed(module, p, signal,
			baseline.Response, rr.Response, false, ""))
	}
	candidate.StabilityRuns = stability
	candidate.TypedReplayHits = typedHits
	return candidate
}

func usesModuleManagedProof(module string) bool {
	switch module {
	case "client_ssti", "idor", "bfla", "mass_assignment", "jwt", "oauth",
		"rate_limit", "account_enum", "race_condition", "business_logic", "file_upload",
		"cache_poisoning", "cache_deception", "cpdos", "broken_auth", "csrf", "smuggling", "websocket", "http_methods",
		"account_recovery", "webhook_security", "tenant_isolation", "session_lifecycle", "secret_exposure":
		return true
	case "hpp":
		return true
	default:
		return false
	}
}

func supportsPolymorphicReplay(module, signal string) bool {
	if module == "sqli" && (signal == "boolean_pair_confirmed" || signal == "union_signal") {
		return false
	}
	return supportsGenericReplay(module)
}

func (r *Runner) replayControl(ctx context.Context, module string, target ScanTarget, original, control payloadgen.Payload,
	probe httpclient.RequestResponse) (httpclient.RequestResponse, bool, error) {
	if supportsGenericReplay(module) {
		rr, err := r.probePayload(ctx, target, control)
		return rr, true, err
	}
	if !supportsRecordedNegativeControl(module) {
		return httpclient.RequestResponse{}, false, nil
	}
	if module == "jwt" {
		rr, err := r.probeWithHeaders(ctx, target, "", map[string]string{"Authorization": "Bearer " + control.Value})
		return rr, true, err
	}
	return r.replayRecordedRequest(ctx, probe.Request, original.Value, control.Value, true)
}

func supportsRecordedNegativeControl(module string) bool {
	switch module {
	case "nosql", "ssrf", "open_redirect", "host_header", "cors", "jwt", "oauth",
		"host_poisoning", "ldap", "xpath", "ldap_xpath_injection", "crlf", "debug_admin", "prototype_pollution":
		return true
	default:
		return false
	}
}

func (r *Runner) replayCandidate(ctx context.Context, module string, target ScanTarget, p payloadgen.Payload,
	probe httpclient.RequestResponse) (httpclient.RequestResponse, bool, error) {
	if supportsGenericReplay(module) {
		rr, err := r.probePayload(ctx, target, p)
		return rr, true, err
	}
	if module == "jwt" {
		rr, err := r.probeWithHeaders(ctx, target, "", map[string]string{"Authorization": "Bearer " + p.Value})
		return rr, true, err
	}
	return r.replayRecordedRequest(ctx, probe.Request, "", "", false)
}

func (r *Runner) replayRecordedRequest(ctx context.Context, request httpclient.RequestRecord, oldValue, newValue string,
	requireReplacement bool) (httpclient.RequestResponse, bool, error) {
	if request.URL == "" || request.Method == "" {
		return httpclient.RequestResponse{}, false, nil
	}
	headers := make(map[string]string, len(request.Headers))
	for key, value := range request.Headers {
		if value == "[REDACTED]" {
			// Persisted evidence intentionally masks session credentials. Do
			// not abort an authenticated proof replay because of that mask:
			// omitting these headers lets the shared HTTP client safely apply
			// its current in-memory session again.
			if isSessionReplayHeader(key) {
				continue
			}
			return httpclient.RequestResponse{}, false, nil
		}
		headers[key] = value
	}
	rawURL, body := request.URL, request.Body
	replaced := false
	if oldValue != "" {
		replacements := [][2]string{{oldValue, newValue}, {url.QueryEscape(oldValue), url.QueryEscape(newValue)}}
		for _, pair := range replacements {
			if strings.Contains(rawURL, pair[0]) {
				rawURL = strings.ReplaceAll(rawURL, pair[0], pair[1])
				replaced = true
			}
			if strings.Contains(body, pair[0]) {
				body = strings.ReplaceAll(body, pair[0], pair[1])
				replaced = true
			}
			for key, value := range headers {
				if strings.Contains(value, pair[0]) {
					headers[key] = strings.ReplaceAll(value, pair[0], pair[1])
					replaced = true
				}
			}
		}
	}
	if requireReplacement && !replaced {
		return httpclient.RequestResponse{}, false, nil
	}
	rr, err := r.client.Do(ctx, request.Method, rawURL, []byte(body), headers)
	return rr, true, err
}

func isSessionReplayHeader(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "cookie", "authorization", "proxy-authorization", "x-api-key", "x-auth-token":
		return true
	default:
		return false
	}
}

func usableNegativeControl(baseline, control httpclient.ResponseRecord) bool {
	if control.StatusCode == 0 || isInfrastructureError(control.StatusCode) ||
		baseline.StatusCode/100 != control.StatusCode/100 {
		return false
	}
	if fp, matched := verification.MatchErrorFingerprint(control.Body, control.StatusCode, control.Headers); matched {
		switch fp.Classification {
		case "waf_block", "generic_error", "login_redirect":
			return false
		}
	}
	return true
}

func negativeControlPayload(module string, target ScanTarget, original payloadgen.Payload) payloadgen.Payload {
	sum := sha256.Sum256([]byte(module + "|" + target.EndpointURL + "|" + target.Parameter + "|" + original.Value))
	marker := "akca-fp-control-" + fmt.Sprintf("%x", sum[:6])
	control := original
	control.Value = marker
	control.Variant = "false_positive_negative_control"
	control.IsControl = true
	control.IsNegativeControl = true
	if module == "xxe" {
		control.Value = "<?xml version=\"1.0\"?><root>" + marker + "</root>"
	}
	if module == "ssti" {
		control.Value = malformedSSTIPayload(original.Value)
	}
	return control
}

func supportsGenericReplay(module string) bool {
	switch module {
	case "xss", "sqli", "ssti", "xxe", "command_injection", "lfi", "crlf":
		return true
	default:
		return false
	}
}

func countTrue(items []bool) int {
	n := 0
	for _, v := range items {
		if v {
			n++
		}
	}
	return n
}

func polymorphicHit(baseline, originalProbe, variantBody string) bool {
	if variantBody == "" {
		return false
	}
	if variantBody == baseline {
		return false
	}
	// Variant must closely match the original probe response, not just differ from baseline.
	// This prevents error pages or random responses from being counted as polymorphic hits.
	if originalProbe != baseline && variantBody == originalProbe {
		return true
	}
	// Allow variant if it's structurally similar to original probe (low diff ratio).
	if originalProbe != baseline && bodyDiffRatio(originalProbe, variantBody) < 0.15 {
		return true
	}
	return false
}

func (r *Runner) buildCandidate(ctx context.Context, module string, target ScanTarget, p payloadgen.Payload,
	baseline, probe httpclient.RequestResponse, signal string) verification.Candidate {
	candidate := verification.Candidate{
		ScanID: r.scanID, Title: module + " on " + target.Parameter, VulnClass: module,
		EndpointURL: target.EndpointURL, Method: target.Method, Parameter: target.Parameter,
		Payload: p.Value, Module: module, Signal: signal,
		Baseline: snapshot(baseline.Response), Probe: snapshot(probe.Response),
		Reflection:         &target.Profile,
		DirectTypedSignal:  true,
		ProofPolicyVersion: verification.CurrentProofPolicyVersion,
		RequestedProofType: verification.DefaultProofType(module),
	}
	baselineObservation := r.observation(module, target, verification.RoleNativeBaseline, 1, baseline)
	if baselineObservation.Valid() {
		candidate.Observations = append(candidate.Observations, baselineObservation)
	}
	probeObservation := r.observation(module, target, verification.RolePositiveProbe, 1, probe)
	if probeObservation.Valid() {
		candidate.Observations = append(candidate.Observations, probeObservation)
	}
	return r.enrichVerification(ctx, module, target, p, baseline, probe, signal, candidate)
}

func (r *Runner) observation(module string, target ScanTarget, role verification.ObservationRole,
	attempt int, rr httpclient.RequestResponse) verification.Observation {
	return verification.NewHTTPObservation(
		r.scanID, module, target.EndpointURL, target.Parameter, target.Location, role, attempt, "",
		rr.Request.Method, rr.Request.URL, rr.Request.Body, rr.Request.Headers, snapshot(rr.Response),
	)
}
