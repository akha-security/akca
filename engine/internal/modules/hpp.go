package modules

import (
	"context"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/safemutation"
	"github.com/akha-security/akca/engine/internal/verification"
	"github.com/akha-security/akca/engine/internal/workflow"
)

func (r *Runner) runHPP(ctx context.Context, target ScanTarget) []ModuleFinding {
	if !r.cfg.AllowsModule("hpp") {
		return nil
	}
	policy, ok := r.hppPolicy(target)
	if !ok {
		if findings := r.runHPPQueryCoverage(ctx, target); len(findings) > 0 {
			return findings
		}
		r.emitStatefulProofGap("hpp", target, "explicit invariant, state and cleanup policy is required")
		r.emitSkip("hpp", target, "explicit invariant, state and cleanup policy is required")
		return nil
	}
	client, ok := r.client.(profiledHTTPDoer)
	if !ok {
		r.emitStatefulProofGap("hpp", target, "isolated recorded requests are unavailable")
		return nil
	}
	profile, ok := r.resolveAuthProfile(policy.AuthProfileID)
	if !ok {
		return nil
	}
	before, err := doRecordedAsProfile(ctx, client, profile, policy.State, nil)
	if err != nil {
		return nil
	}
	guard := r.safeMutationGuard()
	tx, err := guard.Begin(safemutation.Operation{
		ID: "hpp:" + policy.ID, ResourceID: policy.State.URL,
		Risk: safemutation.ReversibleWrite, CleanupDefined: true,
	}, resourceFingerprint(before.Response.Body))
	if err != nil {
		return nil
	}
	finished := false
	defer func() {
		if !finished {
			restored := r.cleanupHPP(ctx, client, profile, policy, before)
			_, _ = guard.Finish(tx.ID, "", restored)
		}
	}()
	control, err := r.probeHPPAsProfile(ctx, client, profile, target, []string{policy.NativeValue}, tx.Canary)
	if err != nil {
		return nil
	}
	afterControl, err := doRecordedAsProfile(ctx, client, profile, policy.State, nil)
	if err != nil || !sameResourceFingerprint(before.Response.Body, afterControl.Response.Body) {
		if err == nil && r.cleanupHPP(ctx, client, profile, policy, before) {
			finished = true
			_, _ = guard.Finish(tx.ID, resourceFingerprint(afterControl.Response.Body), true)
		}
		return nil
	}
	var probes []httpclient.RequestResponse
	var afters []httpclient.RequestResponse
	for attempt := 0; attempt < 2; attempt++ {
		probe, probeErr := r.probeHPPAsProfile(ctx, client, profile, target, policy.DuplicateValues, tx.Canary)
		if probeErr != nil {
			return nil
		}
		after, stateErr := doRecordedAsProfile(ctx, client, profile, policy.State, nil)
		value, valueOK := workflow.ExtractValue(after.Response.Body, policy.StateValueExpression)
		if stateErr != nil || !valueOK || value != policy.ForbiddenValue {
			return nil
		}
		if !r.cleanupHPP(ctx, client, profile, policy, before) {
			return nil
		}
		probes, afters = append(probes, probe), append(afters, after)
	}
	finished = true
	if _, err := guard.Finish(tx.ID, resourceFingerprint(afters[0].Response.Body), true); err != nil {
		return nil
	}
	payload := defaultPayload("hpp", "duplicate_parameter_state_mutation",
		strings.Join(policy.DuplicateValues, ","), "forbidden_state_persisted")
	payload.SelectionReason = policy.ExpectedInvariant
	finding := r.verifyAndBuildWithCandidate(ctx, "hpp", target, payload, before, afters[0],
		"forbidden_state_persisted", false, false, "", "", func(candidate *verification.Candidate) {
			candidate.RequestedProofType = verification.ProofStateMutation
			candidate.NegativeControlSet, candidate.NegativeControlOK = true, true
			candidate.Observations = append(candidate.Observations,
				r.identityObservation("hpp", target, verification.RoleNegativeControl, 1, profile.ID, control),
				r.identityObservation("hpp", target, verification.RoleStateBefore, 1, profile.ID, before),
				r.identityObservation("hpp", target, verification.RoleStateAfter, 1, profile.ID, afters[0]),
				r.identityObservation("hpp", target, verification.RoleStateAfter, 2, profile.ID, afters[1]),
				r.identityObservation("hpp", target, verification.RolePositiveReplay, 2, profile.ID, probes[1]),
			)
		})
	if finding == nil {
		return nil
	}
	finding.Description = policy.ExpectedInvariant + "; duplicate parameters produced the forbidden server state twice, while a single-value control did not, and cleanup restored the original state after each run."
	var out []ModuleFinding
	r.recordFinding(ctx, &out, finding, "hpp", "forbidden_state_persisted")
	return out
}

func (r *Runner) hppPolicy(target ScanTarget) (config.HPPProofPolicy, bool) {
	for _, policy := range r.cfg.HPPProofPolicies {
		if strings.Contains(target.EndpointURL, policy.URLContains) &&
			r.scope.IsInScope(policy.State.URL) && r.scope.IsInScope(policy.Cleanup.URL) {
			return policy, true
		}
	}
	return config.HPPProofPolicy{}, false
}

func (r *Runner) runHPPQueryCoverage(ctx context.Context, target ScanTarget) []ModuleFinding {
	if !strings.EqualFold(target.Method, "GET") || strings.TrimSpace(target.Parameter) == "" {
		return nil
	}
	parsed, err := url.Parse(target.EndpointURL)
	if err != nil || !r.scope.IsInScope(parsed.String()) {
		return nil
	}
	query := parsed.Query()
	nativeValues, ok := query[target.Parameter]
	if !ok || len(nativeValues) == 0 || strings.TrimSpace(nativeValues[0]) == "" {
		return nil
	}
	native := nativeValues[0]
	baseline, err := r.client.Do(ctx, "GET", parsed.String(), nil, r.wafHeadersForModule("hpp", parsed.String()))
	if err != nil {
		return nil
	}
	adminControl, err := r.doHPPQuery(ctx, target, []string{"admin"})
	if err != nil || hppSignal(adminControl.Response.Body, baseline.Response.Body) {
		return nil
	}

	orders := [][]string{{native, "admin"}, {"admin", native}}
	for orderIndex, values := range orders {
		probe, probeErr := r.doHPPQuery(ctx, target, values)
		if probeErr != nil || !hppSignal(probe.Response.Body, baseline.Response.Body) {
			continue
		}
		reverse, reverseErr := r.doHPPQuery(ctx, target, orders[1-orderIndex])
		if reverseErr != nil || hppSignal(reverse.Response.Body, baseline.Response.Body) {
			continue
		}
		var replays []httpclient.RequestResponse
		for attempt := 0; attempt < 2; attempt++ {
			replay, replayErr := r.doHPPQuery(ctx, target, values)
			if replayErr != nil || !hppSignal(replay.Response.Body, baseline.Response.Body) {
				replays = nil
				break
			}
			replays = append(replays, replay)
		}
		if len(replays) != 2 {
			continue
		}

		payloadValue := strings.Join(values, ",")
		payload := defaultPayload("hpp", "duplicate_parameter_privilege_differential", payloadValue,
			"privilege_response_differential")
		finding := r.verifyAndBuildWithCandidate(ctx, "hpp", target, payload, baseline, probe,
			"privilege_response_differential", false, false, "", "", func(candidate *verification.Candidate) {
				candidate.RequestedProofType = verification.ProofDifferentialReplay
				candidate.NegativeControlSet, candidate.NegativeControlOK = true, true
				candidate.TypedReplayHits = []bool{true, true, true}
				candidate.Observations = append(candidate.Observations,
					r.observation("hpp", target, verification.RoleNegativeControl, 1, adminControl),
					r.observation("hpp", target, verification.RoleNegativeControl, 2, reverse),
					r.observation("hpp", target, verification.RolePositiveReplay, 2, replays[0]),
					r.observation("hpp", target, verification.RolePositiveReplay, 3, replays[1]))
			})
		if finding != nil {
			finding.Title = "HTTP Parameter Pollution privilege differential"
			finding.Severity = "high"
			finding.Description = "A duplicated query parameter reproducibly produced an elevated server response. The native request, a single privileged value, and the reverse duplicate order did not; no persistent state mutation is claimed."
			var out []ModuleFinding
			r.recordFinding(ctx, &out, finding, "hpp", "privilege_response_differential")
			return out
		}
	}

	_ = r.emit("hpp_probe_coverage", "HPP duplicate-parameter coverage probe delivered", map[string]interface{}{
		"module":                    "hpp",
		"endpoint":                  target.EndpointURL,
		"parameter":                 target.Parameter,
		"method":                    "GET",
		"status":                    baseline.Response.StatusCode,
		"content_signal_observed":   false,
		"finding_requires_stateful": true,
	})
	return nil
}

func (r *Runner) doHPPQuery(ctx context.Context, target ScanTarget, values []string) (httpclient.RequestResponse, error) {
	parsed, err := url.Parse(target.EndpointURL)
	if err != nil {
		return httpclient.RequestResponse{}, err
	}
	query := parsed.Query()
	query.Del(target.Parameter)
	for _, value := range values {
		query.Add(target.Parameter, value)
	}
	parsed.RawQuery = query.Encode()
	headers := r.wafHeadersForModule("hpp", parsed.String())
	return r.client.Do(ctx, "GET", parsed.String(), nil, headers)
}

func (r *Runner) probeHPPAsProfile(ctx context.Context, client profiledHTTPDoer, profile config.AuthProfile,
	target ScanTarget, values []string, canary string) (httpclient.RequestResponse, error) {
	parsed, err := url.Parse(target.EndpointURL)
	if err != nil {
		return httpclient.RequestResponse{}, err
	}
	query := parsed.Query()
	query.Del(target.Parameter)
	for _, value := range values {
		query.Add(target.Parameter, value)
	}
	parsed.RawQuery = query.Encode()
	headers := map[string]string{"X-Akca-Canary": canary}
	return client.DoWithAuthProfile(ctx, strings.ToUpper(target.Method), parsed.String(), nil, headers, profile)
}

func (r *Runner) cleanupHPP(ctx context.Context, client profiledHTTPDoer, profile config.AuthProfile,
	policy config.HPPProofPolicy, before httpclient.RequestResponse) bool {
	cleanup, err := doRecordedAsProfile(ctx, client, profile, policy.Cleanup, nil)
	if err != nil || !recordedStatusOK(cleanup.Response.StatusCode, policy.Cleanup.ExpectedStatuses) {
		return false
	}
	state, err := doRecordedAsProfile(ctx, client, profile, policy.State, nil)
	return err == nil && sameResourceFingerprint(before.Response.Body, state.Response.Body)
}

func hppSignal(body, baseline string) bool {
	bodyLower := strings.ToLower(body)
	baseLower := strings.ToLower(baseline)
	if strings.TrimSpace(bodyLower) == "" || bodyLower == baseLower || hppLooksLikeEcho(bodyLower) {
		return false
	}
	for _, marker := range []string{
		"role is admin elevated",
		"role\":\"admin\"",
		"role=admin granted",
		"is_admin\":true",
		"admin\":true",
		"permission\":\"admin",
		"privilege\":\"admin",
		"elevated",
		"administrator access",
	} {
		if strings.Contains(bodyLower, marker) && !strings.Contains(baseLower, marker) {
			return true
		}
	}
	return false
}

func hppArraySignal(body, baseline string) bool {
	bodyLower := strings.ToLower(body)
	baseLower := strings.ToLower(baseline)
	if strings.TrimSpace(bodyLower) == "" || bodyLower == baseLower || hppLooksLikeEcho(bodyLower) {
		return false
	}
	if strings.Contains(bodyLower, "admin") && strings.Contains(bodyLower, "elevated") &&
		!strings.Contains(baseLower, "admin") {
		return true
	}
	if strings.Contains(bodyLower, "is_admin\":true") && !strings.Contains(baseLower, "is_admin\":true") {
		return true
	}
	return false
}

func hppLooksLikeEcho(body string) bool {
	for _, marker := range []string{
		"received parameter",
		"submitted array",
		"you sent",
		"echo",
		"request parameter",
		"query parameter",
		"input value",
	} {
		if strings.Contains(body, marker) {
			return true
		}
	}
	return false
}
