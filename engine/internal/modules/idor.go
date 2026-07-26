package modules

import (
	"context"
	"net/http"
	"strings"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/safemutation"
	"github.com/akha-security/akca/engine/internal/verification"
)

func (r *Runner) runIDOR(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("idor", target); !ok {
		r.emitSkip("idor", target, reason)
		return nil
	}
	if len(r.cfg.RoleProfiles) >= 2 && len(r.cfg.ObjectAuthorizationPolicies) > 0 {
		if out := r.runIDORRoleCompare(ctx, target); len(out) > 0 {
			return out
		}
	}
	r.emitOnce("coverage_gap:idor:ownership_contract", "coverage_gap", "BOLA ownership proof contract unavailable or unsatisfied", map[string]interface{}{
		"module": "idor", "endpoint": target.EndpointURL, "required_role_profiles": 2,
		"configured_role_profiles": len(r.cfg.RoleProfiles), "ownership_policies": len(r.cfg.ObjectAuthorizationPolicies),
	})
	// Keyword/status-based cross-account heuristics are coverage signals only.
	// They must never become IDOR findings without a declared owner/foreign
	// resource contract and deterministic identity-bound observations.
	return nil
}

func (r *Runner) runBFLA(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("bfla", target); !ok {
		r.emitSkip("bfla", target, reason)
		return nil
	}
	policy, ok := r.bflaPolicy(target)
	if !ok {
		r.emitSkip("bfla", target, "explicit authorization policy with state and cleanup proof is required")
		return nil
	}
	client, profileCapable := r.client.(profiledHTTPDoer)
	anonymousClient, anonymousCapable := r.client.(sessionlessHTTPDoer)
	if !profileCapable || !anonymousCapable {
		r.emitSkip("bfla", target, "isolated role and anonymous HTTP requests are unavailable")
		return nil
	}
	low, lowOK := r.resolveAuthProfile(policy.LowRoleProfileID)
	high, highOK := r.resolveAuthProfile(policy.HighRoleProfileID)
	if !lowOK || !highOK || low.ID == high.ID {
		return nil
	}

	stateMethod := strings.ToUpper(strings.TrimSpace(policy.StateMethod))
	if stateMethod == "" {
		stateMethod = http.MethodGet
	}
	before, err := client.DoWithAuthProfile(ctx, stateMethod, policy.StateURL, nil, nil, high)
	if err != nil || !successfulResourceResponse(before.Response) {
		return nil
	}
	anonymous, err := anonymousClient.DoWithoutSession(ctx, stateMethod, policy.StateURL, nil, nil)
	if err != nil || (policy.RequireAnonymousDeny && anonymousExposesSameResource(anonymous.Response, before.Response)) {
		return nil
	}

	guard := r.safeMutationGuard()
	tx, err := guard.Begin(safemutation.Operation{
		ID: "bfla:" + policy.ID, ResourceID: policy.StateURL,
		Risk: safemutation.ReversibleWrite, CleanupDefined: true,
	}, resourceFingerprint(before.Response.Body))
	if err != nil {
		return nil
	}
	cleanupOK := false
	defer func() {
		if !cleanupOK {
			restored := r.bflaCleanup(ctx, client, policy, high, before)
			_, _ = guard.Finish(tx.ID, "", restored)
		}
	}()

	actionHeaders := contentTypeHeader(policy.ActionContentType)
	if actionHeaders == nil {
		actionHeaders = map[string]string{}
	}
	actionHeaders["X-Akca-Canary"] = tx.Canary
	lowAction, err := client.DoWithAuthProfile(ctx, strings.ToUpper(policy.Method), target.EndpointURL,
		[]byte(policy.ActionBody), actionHeaders, low)
	if err != nil || lowAction.Response.StatusCode < 200 || lowAction.Response.StatusCode >= 300 {
		return nil
	}
	afterLow, err := client.DoWithAuthProfile(ctx, stateMethod, policy.StateURL, nil, nil, high)
	if err != nil || !successfulResourceResponse(afterLow.Response) ||
		sameResourceFingerprint(before.Response.Body, afterLow.Response.Body) {
		return nil
	}
	if !r.bflaCleanup(ctx, client, policy, high, before) {
		return nil
	}

	// Positive role control: the configured high-privilege identity must cause
	// the same independently observed state transition on the same action.
	highAction, err := client.DoWithAuthProfile(ctx, strings.ToUpper(policy.Method), target.EndpointURL,
		[]byte(policy.ActionBody), actionHeaders, high)
	if err != nil || highAction.Response.StatusCode < 200 || highAction.Response.StatusCode >= 300 {
		return nil
	}
	afterHigh, err := client.DoWithAuthProfile(ctx, stateMethod, policy.StateURL, nil, nil, high)
	if err != nil || !sameResourceFingerprint(afterLow.Response.Body, afterHigh.Response.Body) {
		return nil
	}
	if !r.bflaCleanup(ctx, client, policy, high, before) {
		return nil
	}
	cleanupOK = true
	if _, err := guard.Finish(tx.ID, resourceFingerprint(afterLow.Response.Body), true); err != nil {
		return nil
	}

	p := defaultPayload("bfla", "configured_high_privilege_action", policy.ActionBody, "protected_state_mutation")
	p.SelectionReason = policy.ExpectedRolePolicy
	finding := r.verifyAndBuildWithCandidate(ctx, "bfla", target, p, before, afterLow,
		"protected_state_mutation", false, false, "", "", func(candidate *verification.Candidate) {
			candidate.RequestedProofType = verification.ProofStateMutation
			candidate.NegativeControlSet = true
			candidate.NegativeControlOK = true
			candidate.Observations = append(candidate.Observations,
				r.identityObservation("bfla", target, verification.RoleIdentityA, 1, low.ID, lowAction),
				r.identityObservation("bfla", target, verification.RoleIdentityB, 1, high.ID, highAction),
				r.identityObservation("bfla", target, verification.RoleAnonymousControl, 1, "anonymous", anonymous),
				r.identityObservation("bfla", target, verification.RoleStateBefore, 1, high.ID, before),
				r.identityObservation("bfla", target, verification.RoleStateAfter, 1, low.ID, afterLow),
				r.identityObservation("bfla", target, verification.RoleStateAfter, 2, high.ID, afterHigh),
			)
		})
	if finding == nil {
		return nil
	}
	finding.Title = "BFLA: low-privilege role performed a protected operation"
	finding.Description = "The configured low-privilege role caused the same protected state transition as the high-privilege control; both mutations were independently read and cleaned up."
	var out []ModuleFinding
	r.recordFinding(&out, finding, "bfla", "protected_state_mutation")
	return out
}

func (r *Runner) bflaPolicy(target ScanTarget) (config.AuthorizationPolicy, bool) {
	for _, policy := range r.cfg.AuthorizationPolicies {
		if strings.TrimSpace(policy.ID) == "" || strings.TrimSpace(policy.ExpectedRolePolicy) == "" ||
			strings.TrimSpace(policy.LowRoleProfileID) == "" || strings.TrimSpace(policy.HighRoleProfileID) == "" ||
			strings.TrimSpace(policy.StateURL) == "" || strings.TrimSpace(policy.CleanupURL) == "" ||
			strings.TrimSpace(policy.CleanupMethod) == "" || strings.TrimSpace(policy.Method) == "" {
			continue
		}
		if policy.URLContains != "" && !strings.Contains(target.EndpointURL, policy.URLContains) {
			continue
		}
		if target.Method != "" && !strings.EqualFold(target.Method, policy.Method) {
			continue
		}
		if !r.scope.IsInScope(policy.StateURL) || !r.scope.IsInScope(policy.CleanupURL) {
			continue
		}
		return policy, true
	}
	return config.AuthorizationPolicy{}, false
}

func (r *Runner) bflaCleanup(ctx context.Context, client profiledHTTPDoer, policy config.AuthorizationPolicy,
	high config.AuthProfile, before httpclient.RequestResponse) bool {
	rr, err := client.DoWithAuthProfile(ctx, strings.ToUpper(policy.CleanupMethod), policy.CleanupURL,
		[]byte(policy.CleanupBody), contentTypeHeader(policy.CleanupContentType), high)
	if err != nil || rr.Response.StatusCode < 200 || rr.Response.StatusCode >= 300 {
		return false
	}
	stateMethod := strings.ToUpper(strings.TrimSpace(policy.StateMethod))
	if stateMethod == "" {
		stateMethod = http.MethodGet
	}
	clean, err := client.DoWithAuthProfile(ctx, stateMethod, policy.StateURL, nil, nil, high)
	return err == nil && sameResourceFingerprint(before.Response.Body, clean.Response.Body)
}

func contentTypeHeader(value string) map[string]string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return map[string]string{"Content-Type": value}
}
