package modules

import (
	"context"
	"strings"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/safemutation"
	"github.com/akha-security/akca/engine/internal/verification"
	"github.com/akha-security/akca/engine/internal/workflow"
)

func (r *Runner) runBusinessLogic(ctx context.Context, target ScanTarget) []ModuleFinding {
	if !r.cfg.AllowsModule("business_logic") {
		r.emitSkip("business_logic", target, "disabled by scan config")
		return nil
	}
	policy, ok := r.businessLogicPolicy(target)
	if !ok {
		r.emitStatefulProofGap("business_logic", target, "recorded invariant, state, transaction-ID, and cleanup policy is required")
		r.emitSkip("business_logic", target, "recorded invariant, state, transaction-ID, and cleanup policy is required")
		return nil
	}
	client, ok := r.client.(profiledHTTPDoer)
	if !ok {
		r.emitStatefulProofGap("business_logic", target, "isolated recorded requests are unavailable")
		return nil
	}
	profile, ok := r.resolveAuthProfile(policy.AuthProfileID)
	if !ok {
		return nil
	}
	before, err := doRecordedAsProfile(ctx, client, profile, policy.State, nil)
	if err != nil || !recordedStatusOK(before.Response.StatusCode, policy.State.ExpectedStatuses) {
		return nil
	}
	beforeValue, beforeValueOK := workflow.ExtractValue(before.Response.Body, policy.StateValueExpression)
	if beforeValueOK && beforeValue == policy.ForbiddenValue {
		return nil
	}
	guard := r.safeMutationGuard()
	tx, err := guard.Begin(safemutation.Operation{
		ID: "business_logic:" + policy.ID, ResourceID: policy.State.URL,
		Risk: safemutation.ReversibleWrite, CleanupDefined: true,
	}, resourceFingerprint(before.Response.Body))
	if err != nil {
		return nil
	}
	finished := false
	pendingTransactionID := ""
	defer func() {
		if !finished {
			restored := false
			if pendingTransactionID != "" {
				restored = r.cleanupBusinessTransaction(ctx, client, profile, policy, pendingTransactionID, before)
			}
			_, _ = guard.Finish(tx.ID, "", restored)
		}
	}()

	canaryVariables := map[string]string{"akca_canary": tx.Canary}
	native, err := doRecordedAsProfile(ctx, client, profile, policy.NativeAction, canaryVariables)
	if err != nil || !recordedStatusOK(native.Response.StatusCode, policy.NativeAction.ExpectedStatuses) {
		return nil
	}
	nativeID, nativeIDOK := workflow.ExtractValue(native.Response.Body, policy.TransactionIDExpression)
	if !nativeIDOK || !r.cleanupBusinessTransaction(ctx, client, profile, policy, nativeID, before) {
		return nil
	}

	negative, err := doRecordedAsProfile(ctx, client, profile, policy.NegativeControl, canaryVariables)
	if err != nil || !recordedStatusOK(negative.Response.StatusCode, policy.NegativeControl.ExpectedStatuses) {
		return nil
	}
	if _, transactionCreated := workflow.ExtractValue(negative.Response.Body, policy.TransactionIDExpression); transactionCreated {
		return nil
	}
	afterNegative, err := doRecordedAsProfile(ctx, client, profile, policy.State, nil)
	if err != nil || !sameResourceFingerprint(before.Response.Body, afterNegative.Response.Body) {
		return nil
	}

	manipulated, err := doRecordedAsProfile(ctx, client, profile, policy.ManipulatedAction, canaryVariables)
	if err != nil || !recordedStatusOK(manipulated.Response.StatusCode, policy.ManipulatedAction.ExpectedStatuses) {
		return nil
	}
	transactionID, transactionIDOK := workflow.ExtractValue(manipulated.Response.Body, policy.TransactionIDExpression)
	if !transactionIDOK {
		return nil
	}
	pendingTransactionID = transactionID
	after, err := doRecordedAsProfile(ctx, client, profile, policy.State, nil)
	if err != nil {
		return nil
	}
	afterValue, afterValueOK := workflow.ExtractValue(after.Response.Body, policy.StateValueExpression)
	if !afterValueOK || afterValue != policy.ForbiddenValue ||
		sameResourceFingerprint(before.Response.Body, after.Response.Body) {
		return nil
	}
	if !r.cleanupBusinessTransaction(ctx, client, profile, policy, transactionID, before) {
		return nil
	}
	pendingTransactionID = ""
	finished = true
	if _, err := guard.Finish(tx.ID, resourceFingerprint(after.Response.Body), true); err != nil {
		return nil
	}

	payload := defaultPayload("business_logic", "recorded_invariant_violation",
		policy.ManipulatedAction.Body, "forbidden_state_persisted")
	payload.SelectionReason = policy.ExpectedInvariant
	finding := r.verifyAndBuildWithCandidate(ctx, "business_logic", target, payload, before, after,
		"forbidden_state_persisted", false, false, "", "", func(candidate *verification.Candidate) {
			candidate.RequestedProofType = verification.ProofStateMutation
			candidate.NegativeControlSet = true
			candidate.NegativeControlOK = true
			candidate.Observations = append(candidate.Observations,
				r.identityObservation("business_logic", target, verification.RoleStateBefore, 1, profile.ID, before),
				r.identityObservation("business_logic", target, verification.RoleBaselineReplay, 1, profile.ID, native),
				r.identityObservation("business_logic", target, verification.RoleNegativeControl, 1, profile.ID, negative),
				r.identityObservation("business_logic", target, verification.RoleStateAfter, 1, profile.ID, after),
			)
		})
	if finding == nil {
		return nil
	}
	finding.Title = "Business invariant violation persisted in server state"
	finding.Description = policy.ExpectedInvariant + "; the manipulated transaction created a real transaction ID and the forbidden value persisted in an independent state read before cleanup restored the snapshot."
	var out []ModuleFinding
	r.recordFinding(ctx, &out, finding, "business_logic", "forbidden_state_persisted")
	return out
}

func (r *Runner) businessLogicPolicy(target ScanTarget) (config.BusinessLogicProofPolicy, bool) {
	for _, policy := range r.cfg.BusinessLogicProofPolicies {
		if !strings.Contains(target.EndpointURL, policy.URLContains) ||
			!strings.EqualFold(target.Method, policy.ManipulatedAction.Method) {
			continue
		}
		requests := []config.RecordedRequest{
			policy.NativeAction, policy.ManipulatedAction, policy.NegativeControl, policy.State, policy.Cleanup,
		}
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
	return config.BusinessLogicProofPolicy{}, false
}

func (r *Runner) cleanupBusinessTransaction(ctx context.Context, client profiledHTTPDoer,
	profile config.AuthProfile, policy config.BusinessLogicProofPolicy, transactionID string,
	before httpclient.RequestResponse) bool {
	cleanup, err := doRecordedAsProfile(ctx, client, profile, policy.Cleanup,
		map[string]string{"transaction_id": transactionID})
	if err != nil || !recordedStatusOK(cleanup.Response.StatusCode, policy.Cleanup.ExpectedStatuses) {
		return false
	}
	state, err := doRecordedAsProfile(ctx, client, profile, policy.State, nil)
	return err == nil && sameResourceFingerprint(before.Response.Body, state.Response.Body)
}
