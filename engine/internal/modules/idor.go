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
	if len(r.cfg.RoleProfiles) >= 2 {
		if len(r.cfg.ObjectAuthorizationPolicies) > 0 {
			if out := r.runIDORRoleCompare(ctx, target); len(out) > 0 {
				return out
			}
		}
		if out := r.runIDORHeuristic(ctx, target); len(out) > 0 {
			return out
		}
		r.runIDORHeuristicCoverage(ctx, target)
		r.emitOnce("coverage_gap:idor:ownership_contract", "coverage_gap", "BOLA ownership proof contract unavailable or unsatisfied", map[string]interface{}{
			"module": "idor", "endpoint": target.EndpointURL, "required_role_profiles": 2,
			"configured_role_profiles": len(r.cfg.RoleProfiles), "ownership_policies": len(r.cfg.ObjectAuthorizationPolicies),
		})
		return nil
	}
	if out := r.runIDORHeuristic(ctx, target); len(out) > 0 {
		return out
	}
	r.runIDORHeuristicCoverage(ctx, target)
	return nil
}

func (r *Runner) runIDORHeuristicCoverage(ctx context.Context, target ScanTarget) {
	if strings.TrimSpace(target.Parameter) == "" {
		return
	}
	if strings.ContainsAny(target.EndpointURL, "{}") {
		return
	}
	paramLower := strings.ToLower(target.Parameter)
	isIDParam := false
	for _, kw := range []string{"id", "user_id", "uid", "account", "account_id", "doc", "document", "order", "order_id", "profile", "profile_id", "file_id", "uuid", "user", "member", "ref", "key", "number", "item", "record", "obj", "object", "entity", "resource", "invoice", "ticket", "patient", "customer", "employee", "pid", "cid", "tenant_id", "org_id", "workspace_id", "team_id", "project_id", "company_id", "organization_id", "group_id", "folder_id", "channel_id"} {
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
	if strings.ContainsAny(target.EndpointURL, "{}") {
		return nil
	}
	paramLower := strings.ToLower(target.Parameter)
	isIDParam := false
	for _, kw := range []string{"id", "user_id", "uid", "account", "account_id", "doc", "document", "order", "order_id", "profile", "profile_id", "file_id", "uuid", "user", "member", "ref", "key", "number", "item", "record", "obj", "object", "entity", "resource", "invoice", "ticket", "patient", "customer", "employee", "pid", "cid", "tenant_id", "org_id", "workspace_id", "team_id", "project_id", "company_id", "organization_id", "group_id", "folder_id", "channel_id"} {
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
			// A private record may legitimately contain the same field names as the
			// caller's own baseline object.  What matters is a stable, distinct object
			// value plus a negative control, not absence of the word "email".
			if privateObjectRecordSignal(bodyLower) {
				replay, replayErr := r.probeForModule(ctx, "idor", target, val)
				if replayErr != nil || replay.Response.StatusCode != probeRR.Response.StatusCode ||
					resourceFingerprint(replay.Response.Body) != resourceFingerprint(probeRR.Response.Body) {
					continue
				}
				negativeValue := "akca-nonexistent-" + randomProbeToken()
				negative, negativeErr := r.probeForModule(ctx, "idor", target, negativeValue)
				if negativeErr != nil || (negative.Response.StatusCode == http.StatusOK &&
					resourceFingerprint(negative.Response.Body) == resourceFingerprint(probeRR.Response.Body)) {
					continue
				}
				p := defaultPayload("idor", "parameter_manipulation", val, "unauthenticated_object_access")
				f := r.verifyAndBuildWithCandidate(ctx, "idor", target, p, baseline, probeRR,
					"unauthenticated_object_access", false, false, "", "", func(candidate *verification.Candidate) {
						candidate.RequestedProofType = verification.ProofDifferentialReplay
						candidate.NegativeControlSet = true
						candidate.NegativeControlOK = true
						candidate.TypedReplayHits = []bool{true, true}
						candidate.Observations = append(candidate.Observations,
							r.observation("idor", target, verification.RolePositiveProbe, 1, probeRR),
							r.observation("idor", target, verification.RolePositiveReplay, 2, replay),
							r.observation("idor", target, verification.RoleNegativeControl, 1, negative),
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
		`"invoice_id"`, `"invoice"`, `"amount"`, `"balance"`, `"order_id"`, `"orders"`,
		`"message"`, `"messages"`, `"patient"`, `"medical"`, `"tenant_id"`, `"organization_id"`,
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
		if findings := r.runBFLAReadOnlyHeuristic(ctx, target); len(findings) > 0 {
			return findings
		}
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

func (r *Runner) runBFLAReadOnlyHeuristic(ctx context.Context, target ScanTarget) []ModuleFinding {
	method := strings.ToUpper(strings.TrimSpace(target.Method))
	if method == "" {
		method = http.MethodGet
	}
	if method != http.MethodGet && method != http.MethodHead || !looksLikePrivilegedRoute(target.EndpointURL) {
		return nil
	}
	client, profileCapable := r.client.(profiledHTTPDoer)
	anonymousClient, anonymousCapable := r.client.(sessionlessHTTPDoer)
	if !profileCapable || !anonymousCapable {
		return nil
	}
	privileged, unprivileged, ok := r.heuristicPrivilegeProfiles()
	if !ok {
		return nil
	}
	high, err := client.DoWithAuthProfile(ctx, method, target.EndpointURL, nil, nil, privileged)
	if err != nil || !successfulResourceResponse(high.Response) || !privateAuthResourceEvidence(high.Response.Body) {
		return nil
	}
	low, err := client.DoWithAuthProfile(ctx, method, target.EndpointURL, nil, nil, unprivileged)
	if err != nil || !successfulResourceResponse(low.Response) ||
		!sameResourceFingerprint(high.Response.Body, low.Response.Body) {
		return nil
	}
	anonymous, err := anonymousClient.DoWithoutSession(ctx, method, target.EndpointURL, nil, nil)
	if err != nil || anonymousExposesSameResource(anonymous.Response, high.Response) {
		return nil
	}
	highReplay, err := client.DoWithAuthProfile(ctx, method, target.EndpointURL, nil, nil, privileged)
	if err != nil || !sameResourceFingerprint(high.Response.Body, highReplay.Response.Body) {
		return nil
	}
	lowReplay, err := client.DoWithAuthProfile(ctx, method, target.EndpointURL, nil, nil, unprivileged)
	if err != nil || !sameResourceFingerprint(low.Response.Body, lowReplay.Response.Body) {
		return nil
	}

	payload := defaultPayload("bfla", "read_only_role_boundary", unprivileged.ID, "privileged_read_access")
	finding := r.verifyAndBuildWithCandidate(ctx, "bfla", target, payload, anonymous, low,
		"privileged_read_access", false, false, "", "", func(candidate *verification.Candidate) {
			candidate.RequestedProofType = verification.ProofIdentityBoundary
			candidate.NegativeControlSet, candidate.NegativeControlOK = true, true
			candidate.TypedReplayHits = []bool{true, true}
			candidate.Observations = append(candidate.Observations,
				r.identityObservation("bfla", target, verification.RoleIdentityA, 1, privileged.ID, high),
				r.identityObservation("bfla", target, verification.RoleIdentityA, 2, privileged.ID, highReplay),
				r.identityObservation("bfla", target, verification.RoleIdentityB, 1, unprivileged.ID, low),
				r.identityObservation("bfla", target, verification.RoleIdentityB, 2, unprivileged.ID, lowReplay),
				r.identityObservation("bfla", target, verification.RoleAnonymousControl, 1, "anonymous", anonymous))
		})
	if finding == nil {
		return nil
	}
	finding.Title = "BFLA: low-privilege role read a privileged endpoint"
	finding.Severity = "high"
	finding.Description = "A role explicitly identified as non-privileged retrieved the same stable private resource as the privileged role across independent GET/HEAD replays, while the anonymous control was denied. No state-changing request was sent."
	var out []ModuleFinding
	r.recordFinding(ctx, &out, finding, "bfla", "privileged_read_access")
	return out
}

func (r *Runner) heuristicPrivilegeProfiles() (config.AuthProfile, config.AuthProfile, bool) {
	var privileged, unprivileged config.AuthProfile
	for _, role := range r.cfg.RoleProfiles {
		profile, ok := r.resolveAuthProfile(role.AuthProfileID)
		if !ok {
			continue
		}
		label := strings.ToLower(role.ID + " " + role.Name + " " + profile.ID + " " + profile.Name)
		if strings.Contains(label, "admin") || strings.Contains(label, "superuser") ||
			strings.Contains(label, "privileged") || strings.Contains(label, "high") {
			if privileged.ID == "" {
				privileged = profile
			}
			continue
		}
		if unprivileged.ID == "" {
			unprivileged = profile
		}
	}
	return privileged, unprivileged, privileged.ID != "" && unprivileged.ID != "" && privileged.ID != unprivileged.ID
}

func looksLikePrivilegedRoute(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	path := strings.ToLower(parsed.Path)
	for _, marker := range []string{"/admin", "/manage", "/management", "/internal", "/staff", "/superuser"} {
		if strings.Contains(path, marker) {
			return true
		}
	}
	return false
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
