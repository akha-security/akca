package modules

import (
	"context"
	"strings"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/safemutation"
	"github.com/akha-security/akca/engine/internal/verification"
)

type statefulSecurityFinding struct {
	Signal      string
	Variant     string
	Title       string
	Description string
	Severity    string
}

func (r *Runner) runStatefulSecurityProof(ctx context.Context, module string, target ScanTarget,
	policies []config.StatefulSecurityProofPolicy, details statefulSecurityFinding) []ModuleFinding {
	policy, ok := r.statefulSecurityPolicy(target, policies)
	if !ok {
		r.emitStatefulProofGap(module, target, "recorded state, negative-control, and cleanup policy is required")
		r.emitSkip(module, target, "recorded state, negative-control, and cleanup policy is required")
		return nil
	}
	client, ok := r.client.(profiledHTTPDoer)
	if !ok {
		r.emitStatefulProofGap(module, target, "isolated recorded requests are unavailable")
		r.emitSkip(module, target, "isolated recorded requests are unavailable")
		return nil
	}
	profile := config.AuthProfile{ID: "anonymous", Name: "Anonymous"}
	if strings.TrimSpace(policy.AuthProfileID) != "" {
		var found bool
		profile, found = r.resolveAuthProfile(policy.AuthProfileID)
		if !found {
			return nil
		}
	}

	before, err := doRecordedAsProfile(ctx, client, profile, policy.State, nil)
	if err != nil || !recordedStatusOK(before.Response.StatusCode, policy.State.ExpectedStatuses) {
		return nil
	}
	guard := r.safeMutationGuard()
	tx, err := guard.Begin(safemutation.Operation{
		ID: module + ":" + policy.ID, ResourceID: policy.State.URL,
		Risk: safemutation.ReversibleWrite, CleanupDefined: true,
	}, resourceFingerprint(before.Response.Body))
	if err != nil {
		return nil
	}
	finished := false
	writeAttempted := false
	defer func() {
		if finished {
			return
		}
		restored := !writeAttempted || r.cleanupStatefulSecurityProof(ctx, client, profile, policy, before)
		_, _ = guard.Finish(tx.ID, "", restored)
	}()
	variables := map[string]string{"akca_canary": tx.Canary}

	writeAttempted = true
	negative, err := doRecordedAsProfile(ctx, client, profile, policy.NegativeControl, variables)
	if err != nil || !recordedStatusOK(negative.Response.StatusCode, policy.NegativeControl.ExpectedStatuses) {
		return nil
	}
	afterNegative, err := doRecordedAsProfile(ctx, client, profile, policy.State, nil)
	if err != nil || !sameResourceFingerprint(before.Response.Body, afterNegative.Response.Body) {
		return nil
	}

	action, err := doRecordedAsProfile(ctx, client, profile, policy.Action, variables)
	if err != nil || !recordedStatusOK(action.Response.StatusCode, policy.Action.ExpectedStatuses) {
		return nil
	}
	after, err := doRecordedAsProfile(ctx, client, profile, policy.State, nil)
	if err != nil || !recordedStatusOK(after.Response.StatusCode, policy.State.ExpectedStatuses) ||
		sameResourceFingerprint(before.Response.Body, after.Response.Body) {
		return nil
	}
	if !r.cleanupStatefulSecurityProof(ctx, client, profile, policy, before) {
		return nil
	}
	finished = true
	if _, err := guard.Finish(tx.ID, resourceFingerprint(after.Response.Body), true); err != nil {
		return nil
	}

	payload := defaultPayload(module, details.Variant, policy.Action.Body, details.Signal)
	payload.SelectionReason = policy.ExpectedInvariant
	finding := r.verifyAndBuildWithCandidate(ctx, module, target, payload, before, after,
		details.Signal, false, false, "", "", func(candidate *verification.Candidate) {
			candidate.RequestedProofType = verification.ProofStateMutation
			candidate.NegativeControlSet = true
			candidate.NegativeControlOK = true
			candidate.Observations = append(candidate.Observations,
				r.identityObservation(module, target, verification.RoleStateBefore, 1, profile.ID, before),
				r.identityObservation(module, target, verification.RoleNegativeControl, 1, profile.ID, negative),
				r.identityObservation(module, target, verification.RoleNegativeControl, 2, profile.ID, afterNegative),
				r.identityObservation(module, target, verification.RoleStateAfter, 1, profile.ID, after),
			)
		})
	if finding == nil {
		return nil
	}
	finding.Title = details.Title
	finding.Description = policy.ExpectedInvariant + "; " + details.Description
	finding.Severity = details.Severity
	var out []ModuleFinding
	r.recordFinding(ctx, &out, finding, module, details.Signal)
	return out
}

func (r *Runner) statefulSecurityPolicy(target ScanTarget,
	policies []config.StatefulSecurityProofPolicy) (config.StatefulSecurityProofPolicy, bool) {
	for _, policy := range policies {
		if !strings.Contains(target.EndpointURL, policy.URLContains) ||
			!strings.EqualFold(target.Method, policy.Action.Method) {
			continue
		}
		requests := []config.RecordedRequest{policy.Action, policy.NegativeControl, policy.State, policy.Cleanup}
		inScope := true
		for _, request := range requests {
			if !r.scope.IsInScope(request.URL) {
				inScope = false
				break
			}
		}
		if inScope {
			return policy, true
		}
	}
	return config.StatefulSecurityProofPolicy{}, false
}

func (r *Runner) cleanupStatefulSecurityProof(ctx context.Context, client profiledHTTPDoer,
	profile config.AuthProfile, policy config.StatefulSecurityProofPolicy, before httpclient.RequestResponse) bool {
	cleanup, err := doRecordedAsProfile(ctx, client, profile, policy.Cleanup, nil)
	if err != nil || !recordedStatusOK(cleanup.Response.StatusCode, policy.Cleanup.ExpectedStatuses) {
		return false
	}
	state, err := doRecordedAsProfile(ctx, client, profile, policy.State, nil)
	return err == nil && recordedStatusOK(state.Response.StatusCode, policy.State.ExpectedStatuses) &&
		sameResourceFingerprint(before.Response.Body, state.Response.Body)
}

func (r *Runner) emitStatefulProofGap(module string, target ScanTarget, reason string) {
	r.emitOnce("stateful-proof-gap:"+module+":"+target.EndpointURL, "coverage_gap",
		"Stateful proof coverage requires an explicit reversible policy",
		map[string]interface{}{
			"module":                    module,
			"endpoint":                  target.EndpointURL,
			"method":                    target.Method,
			"parameter":                 target.Parameter,
			"reason":                    reason,
			"finding_requires_stateful": true,
			"mutation_probe_delivered":  false,
		})
}
