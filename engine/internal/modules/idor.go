package modules

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/mutation"
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
	r.runIDORHeuristicCoverage(ctx, target)
	r.emitOnce("coverage_gap:idor:ownership_contract", "coverage_gap", "BOLA ownership proof contract unavailable or unsatisfied", map[string]interface{}{
		"module": "idor", "endpoint": target.EndpointURL, "required_role_profiles": 2,
		"configured_role_profiles": len(r.cfg.RoleProfiles), "ownership_policies": len(r.cfg.ObjectAuthorizationPolicies),
	})
	return nil
}

func (r *Runner) runIDORHeuristicCoverage(ctx context.Context, target ScanTarget) {
	if !strings.EqualFold(target.Method, http.MethodGet) || strings.TrimSpace(target.Parameter) == "" {
		return
	}
	if strings.ContainsAny(target.EndpointURL, "{}") {
		return
	}
	paramLower := strings.ToLower(target.Parameter)
	isIDParam := false
	for _, kw := range []string{"id", "user_id", "uid", "account", "account_id", "doc", "document", "order", "order_id", "profile", "profile_id", "file_id", "uuid", "user", "member", "ref", "key", "number", "item", "record", "obj", "object", "entity", "resource", "invoice", "ticket", "patient", "customer", "employee", "pid", "cid"} {
		if paramLower == kw || strings.HasSuffix(paramLower, "_id") || strings.HasSuffix(paramLower, "id") {
			isIDParam = true
			break
		}
	}
	if !isIDParam {
		return
	}
	baseline, err := r.cachedEmptyProbe(ctx, target)
	if err != nil || baseline.Response.StatusCode >= 400 {
		return
	}
	origVal := nativeTargetValue(target)
	if origVal == "" {
		origVal = "100"
		if u, err := url.Parse(target.EndpointURL); err == nil {
			if qVal := u.Query().Get(target.Parameter); qVal != "" {
				origVal = qVal
			}
		}
	}
	hint := &mutation.SchemaHint{ParamName: target.Parameter}
	vType := mutation.Classify(origVal, hint)
	mSet := mutation.Generate(origVal, vType, nil)
	var payloads []string
	if n, err := strconv.ParseInt(origVal, 10, 64); err == nil {
		payloads = append(payloads, strconv.FormatInt(n+1, 10), strconv.FormatInt(n-1, 10), strconv.FormatInt(n+2, 10))
	} else if len(origVal) == 36 && strings.Count(origVal, "-") == 4 {
		lastChar := origVal[len(origVal)-1]
		newChar := "1"
		if lastChar == '1' {
			newChar = "2"
		}
		payloads = append(payloads, origVal[:len(origVal)-1]+newChar)
	}
	payloads = append(payloads, "102", "1", "999999", "00000000-0000-0000-0000-000000000001")
	for _, mut := range mSet.Mutations {
		if mut.Value != "" && mut.Value != origVal {
			payloads = append(payloads, mut.Value)
		}
	}
	probesSent := 0
	sensitiveDistinct := false
	for _, value := range payloads {
		if probesSent >= 5 || ctx.Err() != nil {
			break
		}
		rr, err := r.probeForModule(ctx, "idor", target, value)
		if err != nil {
			continue
		}
		probesSent++
		bodyLower := strings.ToLower(rr.Response.Body)
		if rr.Response.StatusCode == http.StatusOK &&
			resourceFingerprint(rr.Response.Body) != resourceFingerprint(baseline.Response.Body) &&
			privateObjectRecordSignal(bodyLower) {
			sensitiveDistinct = true
		}
	}
	if probesSent == 0 {
		return
	}
	_ = r.emit("idor_heuristic_probe_coverage", "IDOR read-only heuristic probes delivered; ownership proof is required before reporting", map[string]interface{}{
		"module":                          "idor",
		"endpoint":                        target.EndpointURL,
		"parameter":                       target.Parameter,
		"probes_sent":                     probesSent,
		"sensitive_distinct_observed":     sensitiveDistinct,
		"finding_requires_identity_proof": true,
	})
}

func (r *Runner) runIDORHeuristic(ctx context.Context, target ScanTarget) []ModuleFinding {
	paramLower := strings.ToLower(target.Parameter)
	isIDParam := false
	for _, kw := range []string{"id", "user_id", "uid", "account", "account_id", "doc", "document", "order", "order_id", "profile", "profile_id", "file_id", "uuid", "user", "member", "ref", "key", "number", "item", "record", "obj", "object", "entity", "resource", "invoice", "ticket", "patient", "customer", "employee", "pid", "cid"} {
		if paramLower == kw || strings.HasSuffix(paramLower, "_id") || strings.HasSuffix(paramLower, "id") {
			isIDParam = true
			break
		}
	}
	if !isIDParam {
		return nil
	}

	baseline, err := r.cachedEmptyProbe(ctx, target)
	if err != nil || baseline.Response.StatusCode >= 400 || len(baseline.Response.Body) < 10 {
		return nil
	}

	// Extract original value of parameter if present in URL
	origVal := "100"
	if u, err := url.Parse(target.EndpointURL); err == nil {
		if qVal := u.Query().Get(target.Parameter); qVal != "" {
			origVal = qVal
		}
	}

	// Try probing with smart semantic parameter mutations
	hint := &mutation.SchemaHint{ParamName: target.Parameter}
	vType := mutation.Classify(origVal, hint)
	mSet := mutation.Generate(origVal, vType, nil)

	idorPayloads := []string{"102", "1", "100", "999999", "00000000-0000-0000-0000-000000000001"}
	for _, mut := range mSet.Mutations {
		if mut.Value != "" && mut.Value != origVal {
			idorPayloads = append(idorPayloads, mut.Value)
		}
	}
	var out []ModuleFinding

	for _, val := range idorPayloads {
		if ctx.Err() != nil {
			break
		}
		probeRR, probeErr := r.probeForModule(ctx, "idor", target, val)
		if probeErr != nil || probeRR.Response.StatusCode != 200 {
			continue
		}
		bodyLower := strings.ToLower(probeRR.Response.Body)
		if strings.Contains(bodyLower, "unauthorized") || strings.Contains(bodyLower, "forbidden") || strings.Contains(bodyLower, "login") {
			continue
		}
		// Must return valid object data with distinct fingerprint from baseline
		if resourceFingerprint(probeRR.Response.Body) != resourceFingerprint(baseline.Response.Body) {
			lengthDiff := len(probeRR.Response.Body) - len(baseline.Response.Body)
			if lengthDiff < 0 {
				lengthDiff = -lengthDiff
			}
			// Must return sensitive private user/account attributes or tenant-specific records
			hasSensitiveRecord := strings.Contains(bodyLower, `"email"`) || strings.Contains(bodyLower, `"password"`) ||
				strings.Contains(bodyLower, `"token"`) || strings.Contains(bodyLower, `"credit_card"`) ||
				strings.Contains(bodyLower, `"ssn"`) || strings.Contains(bodyLower, `"billing"`) ||
				strings.Contains(bodyLower, `"api_key"`) || strings.Contains(bodyLower, `"secret"`) ||
				strings.Contains(bodyLower, `"phone"`) || strings.Contains(bodyLower, `"address"`) ||
				strings.Contains(bodyLower, `"user_id"`) || strings.Contains(bodyLower, `"account_number"`)

			if hasSensitiveRecord && !strings.Contains(strings.ToLower(baseline.Response.Body), `"email"`) {
				p := defaultPayload("idor", "parameter_manipulation", val, "unauthenticated_object_access")
				f := r.verifyAndBuildWithCandidate(ctx, "idor", target, p, baseline, probeRR,
					"unauthenticated_object_access", false, false, "", "", func(candidate *verification.Candidate) {
						candidate.RequestedProofType = verification.ProofDifferentialReplay
						candidate.Observations = append(candidate.Observations,
							r.observation("idor", target, verification.RolePositiveProbe, 1, probeRR),
						)
					})
				if f != nil {
					f.Title = "IDOR / BOLA: Unauthorized Access to Object via Parameter Manipulation (" + target.Parameter + "=" + val + ")"
					f.Severity = "high"
					f.Description = "Modifying the parameter " + target.Parameter + " to " + val + " returned HTTP 200 OK with private user/account data without proper authorization checks."
					r.recordFinding(ctx, &out, f, "idor", "unauthenticated_object_access")
					break
				}
			}
		}
	}
	return out
}

func privateObjectRecordSignal(bodyLower string) bool {
	for _, marker := range []string{
		`"email"`, `"password"`, `"token"`, `"credit_card"`, `"ssn"`, `"billing"`,
		`"api_key"`, `"secret"`, `"phone"`, `"address"`, `"user_id"`, `"account_number"`,
	} {
		if strings.Contains(bodyLower, marker) {
			return true
		}
	}
	return false
}

func (r *Runner) runBFLA(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("bfla", target); !ok {
		r.emitSkip("bfla", target, reason)
		return nil
	}
	policy, ok := r.bflaPolicy(target)
	if !ok {
		r.emitStatefulProofGap("bfla", target, "explicit authorization policy with state and cleanup proof is required")
		r.emitSkip("bfla", target, "explicit authorization policy with state and cleanup proof is required")
		return nil
	}
	client, profileCapable := r.client.(profiledHTTPDoer)
	anonymousClient, anonymousCapable := r.client.(sessionlessHTTPDoer)
	if !profileCapable || !anonymousCapable {
		r.emitStatefulProofGap("bfla", target, "isolated role and anonymous HTTP requests are unavailable")
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
	r.recordFinding(ctx, &out, finding, "bfla", "protected_state_mutation")
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
