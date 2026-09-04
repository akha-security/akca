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
		r.runHPPQueryCoverage(ctx, target)
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

func (r *Runner) runHPPQueryCoverage(ctx context.Context, target ScanTarget) {
	if !strings.EqualFold(target.Method, "GET") || strings.TrimSpace(target.Parameter) == "" {
		return
	}
	parsed, err := url.Parse(target.EndpointURL)
	if err != nil || !r.scope.IsInScope(parsed.String()) {
		return
	}
	query := parsed.Query()
	if _, ok := query[target.Parameter]; !ok {
		return
	}
	query.Add(target.Parameter, "akca-hpp-"+randomAccountNonce())
	parsed.RawQuery = query.Encode()
	if !r.scope.IsInScope(parsed.String()) {
		return
	}
	headers := r.wafHeadersForModule("hpp", parsed.String())
	rr, err := r.client.Do(ctx, "GET", parsed.String(), nil, headers)
	if err != nil {
		return
	}
	_ = r.emit("hpp_probe_coverage", "HPP duplicate-parameter coverage probe delivered", map[string]interface{}{
		"module":                    "hpp",
		"endpoint":                  target.EndpointURL,
		"parameter":                 target.Parameter,
		"method":                    "GET",
		"status":                    rr.Response.StatusCode,
		"content_signal_observed":   hppSignal(rr.Response.Body, ""),
		"finding_requires_stateful": true,
	})
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
