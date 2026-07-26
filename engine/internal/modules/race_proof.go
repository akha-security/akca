package modules

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/safemutation"
	"github.com/akha-security/akca/engine/internal/verification"
	"github.com/akha-security/akca/engine/internal/workflow"
)

func (r *Runner) runRaceConditionProof(ctx context.Context, target ScanTarget) []ModuleFinding {
	if !r.cfg.AllowsModule("race_condition") {
		r.emitSkip("race_condition", target, "disabled by scan config")
		return nil
	}
	policy, ok := r.racePolicy(target)
	if !ok {
		r.emitSkip("race_condition", target, "recorded transaction-ID and cleanup policy is required")
		return nil
	}
	client, ok := r.client.(profiledHTTPDoer)
	if !ok {
		r.emitSkip("race_condition", target, "isolated authenticated requests are unavailable")
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
	guard := r.safeMutationGuard()
	tx, err := guard.Begin(safemutation.Operation{
		ID: "race:" + policy.ID, ResourceID: policy.State.URL,
		Risk: safemutation.ReversibleWrite, CleanupDefined: true,
	}, resourceFingerprint(before.Response.Body))
	if err != nil {
		return nil
	}
	finished := false
	knownTransactionIDs := make(map[string]struct{})
	defer func() {
		if !finished {
			restored := len(knownTransactionIDs) > 0 &&
				r.cleanupRaceTransactions(ctx, client, profile, policy, knownTransactionIDs, before)
			_, _ = guard.Finish(tx.ID, "", restored)
		}
	}()
	canaryVariables := map[string]string{"akca_canary": tx.Canary}

	sequentialRuns := policy.SequentialRuns
	if sequentialRuns == 0 {
		sequentialRuns = 5
	}
	var sequentialResponses []httpclient.RequestResponse
	sequentialIDs := make(map[string]struct{})
	for index := 0; index < sequentialRuns; index++ {
		rr, requestErr := doRecordedAsProfile(ctx, client, profile, policy.Action, canaryVariables)
		if requestErr != nil {
			return nil
		}
		sequentialResponses = append(sequentialResponses, rr)
		if transactionID, extracted := workflow.ExtractValue(rr.Response.Body, policy.TransactionIDExpression); extracted {
			sequentialIDs[transactionID] = struct{}{}
			knownTransactionIDs[transactionID] = struct{}{}
		}
	}
	if len(sequentialIDs) != 1 {
		// A valid sequential control must prove that the business rule allows
		// exactly one side effect; zero is an unusable fixture and >1 is already
		// broken without concurrency.
		return nil
	}
	if !r.cleanupRaceTransactions(ctx, client, profile, policy, sequentialIDs, before) {
		return nil
	}
	clear(knownTransactionIDs)

	concurrentRuns := policy.ConcurrentRuns
	if concurrentRuns == 0 {
		concurrentRuns = 5
	}
	start := make(chan struct{})
	results := make(chan httpclient.RequestResponse, concurrentRuns)
	errors := make(chan error, concurrentRuns)
	var wg sync.WaitGroup
	for index := 0; index < concurrentRuns; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-start:
			case <-ctx.Done():
				errors <- ctx.Err()
				return
			}
			rr, requestErr := doRecordedAsProfile(ctx, client, profile, policy.Action, canaryVariables)
			if requestErr != nil {
				errors <- requestErr
				return
			}
			results <- rr
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(errors)
	if len(errors) > 0 {
		return nil
	}
	concurrentIDs := make(map[string]struct{})
	var concurrentResponses []httpclient.RequestResponse
	for rr := range results {
		concurrentResponses = append(concurrentResponses, rr)
		if transactionID, extracted := workflow.ExtractValue(rr.Response.Body, policy.TransactionIDExpression); extracted {
			concurrentIDs[transactionID] = struct{}{}
			knownTransactionIDs[transactionID] = struct{}{}
		}
	}
	if len(concurrentIDs) < 2 {
		return nil
	}
	after, err := doRecordedAsProfile(ctx, client, profile, policy.State, nil)
	if err != nil || sameResourceFingerprint(before.Response.Body, after.Response.Body) {
		return nil
	}
	if !r.cleanupRaceTransactions(ctx, client, profile, policy, concurrentIDs, before) {
		return nil
	}
	clear(knownTransactionIDs)
	finished = true
	if _, err := guard.Finish(tx.ID, resourceFingerprint(after.Response.Body), true); err != nil {
		return nil
	}

	payload := defaultPayload("race_condition", "synchronized_transaction_replay",
		policy.Action.Body, "multiple_unique_side_effects")
	finding := r.verifyAndBuildWithCandidate(ctx, "race_condition", target, payload, before, after,
		"multiple_unique_side_effects", false, false, "", "", func(candidate *verification.Candidate) {
			candidate.RequestedProofType = verification.ProofStateMutation
			candidate.NegativeControlSet = true
			candidate.NegativeControlOK = true
			candidate.Observations = append(candidate.Observations,
				r.identityObservation("race_condition", target, verification.RoleStateBefore, 1, profile.ID, before),
				r.identityObservation("race_condition", target, verification.RoleNegativeControl, 1, profile.ID, sequentialResponses[0]),
				r.identityObservation("race_condition", target, verification.RoleStateAfter, 1, profile.ID, after),
			)
			for index, rr := range concurrentResponses {
				if _, extracted := workflow.ExtractValue(rr.Response.Body, policy.TransactionIDExpression); extracted {
					candidate.Observations = append(candidate.Observations,
						r.identityObservation("race_condition", target, verification.RolePositiveReplay, index+2, profile.ID, rr))
				}
			}
		})
	if finding == nil {
		return nil
	}
	finding.Title = "Race condition produced multiple unique side effects"
	finding.Description = "Sequential control produced one transaction ID; a synchronized concurrent batch produced multiple unique transaction IDs, changed server state, and cleanup restored the snapshot."
	var out []ModuleFinding
	r.recordFinding(&out, finding, "race_condition", "multiple_unique_side_effects")
	return out
}

func (r *Runner) racePolicy(target ScanTarget) (config.RaceProofPolicy, bool) {
	for _, policy := range r.cfg.RaceProofPolicies {
		if strings.Contains(target.EndpointURL, policy.URLContains) &&
			strings.EqualFold(target.Method, policy.Action.Method) &&
			r.scope.IsInScope(policy.Action.URL) && r.scope.IsInScope(policy.State.URL) &&
			r.scope.IsInScope(policy.Cleanup.URL) {
			return policy, true
		}
	}
	return config.RaceProofPolicy{}, false
}

func (r *Runner) cleanupRaceTransactions(ctx context.Context, client profiledHTTPDoer,
	profile config.AuthProfile, policy config.RaceProofPolicy, transactionIDs map[string]struct{},
	before httpclient.RequestResponse) bool {
	for transactionID := range transactionIDs {
		cleanup, err := doRecordedAsProfile(ctx, client, profile, policy.Cleanup,
			map[string]string{"transaction_id": transactionID})
		if err != nil || !recordedStatusOK(cleanup.Response.StatusCode, policy.Cleanup.ExpectedStatuses) {
			return false
		}
	}
	state, err := doRecordedAsProfile(ctx, client, profile, policy.State, nil)
	return err == nil && sameResourceFingerprint(before.Response.Body, state.Response.Body)
}

func doRecordedAsProfile(ctx context.Context, client profiledHTTPDoer, profile config.AuthProfile,
	request config.RecordedRequest, variables map[string]string) (httpclient.RequestResponse, error) {
	method := strings.ToUpper(strings.TrimSpace(request.Method))
	if method == "" {
		method = http.MethodGet
	}
	rawURL := bindRecordedValue(request.URL, variables)
	body := bindRecordedValue(request.Body, variables)
	if strings.Contains(rawURL, "{{") || strings.Contains(body, "{{") {
		return httpclient.RequestResponse{}, fmt.Errorf("recorded request contains unresolved workflow binding")
	}
	headers := contentTypeHeader(request.ContentType)
	if canary := strings.TrimSpace(variables["akca_canary"]); canary != "" {
		if headers == nil {
			headers = map[string]string{}
		}
		headers["X-Akca-Canary"] = canary
	}
	return client.DoWithAuthProfile(ctx, method, rawURL, []byte(body), headers, profile)
}

func bindRecordedValue(value string, variables map[string]string) string {
	for key, replacement := range variables {
		value = strings.ReplaceAll(value, "{{"+key+"}}", replacement)
	}
	return value
}

func recordedStatusOK(status int, expected []int) bool {
	if len(expected) == 0 {
		return status >= 200 && status < 400
	}
	for _, candidate := range expected {
		if status == candidate {
			return true
		}
	}
	return false
}
