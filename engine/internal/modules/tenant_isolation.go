package modules

import (
	"context"

	"github.com/akha-security/akca/engine/internal/verification"
)

// Tenant isolation is an ownership assertion, not a response-difference
// heuristic. It runs only against resources explicitly declared as owned by
// one role and forbidden to another role.
func (r *Runner) runTenantIsolation(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("tenant_isolation", target); !ok {
		r.emitSkip("tenant_isolation", target, reason)
		return nil
	}
	policy, ok := r.bolaPolicy(target)
	if !ok {
		r.emitStatefulProofGap("tenant_isolation", target, "explicit ownership policy with owner, foreign, and anonymous identities is required")
		r.emitSkip("tenant_isolation", target, "explicit ownership policy with owner, foreign, and anonymous identities is required")
		return nil
	}
	client, ok := r.client.(sessionlessHTTPDoer)
	if !ok {
		r.emitStatefulProofGap("tenant_isolation", target, "anonymous authorization control unavailable")
		r.emitSkip("tenant_isolation", target, "anonymous authorization control unavailable")
		return nil
	}
	ownerRole, ownerAuth, ownerOK := r.resolveRoleProfile(policy.OwnerRoleProfileID)
	foreignRole, foreignAuth, foreignOK := r.resolveRoleProfile(policy.ForeignRoleProfileID)
	if !ownerOK || !foreignOK {
		return nil
	}
	proofTarget := target
	proofTarget.Parameter = policy.Parameter
	proofTarget.Location = policy.Location
	if proofTarget.Location == "" {
		proofTarget.Location = target.Location
	}

	for _, resourceValue := range policy.ResourceValues {
		owner, err := r.probeAsProfileWithValue(ctx, ownerAuth, proofTarget, policy.Parameter, resourceValue)
		if err != nil || !successfulResourceResponse(owner.Response) {
			continue
		}
		foreign, err := r.probeAsProfileWithValue(ctx, foreignAuth, proofTarget, policy.Parameter, resourceValue)
		if err != nil || !successfulResourceResponse(foreign.Response) ||
			!sameResourceFingerprint(owner.Response.Body, foreign.Response.Body) {
			continue
		}
		anonymousURL, anonymousBody, anonymousHeaders, err := buildAuthorizationRequest(proofTarget, policy.Parameter, resourceValue)
		if err != nil {
			continue
		}
		anonymous, err := client.DoWithoutSession(ctx, effectiveMethod(target.Method, proofTarget.Location),
			anonymousURL, anonymousBody, anonymousHeaders)
		if err != nil || anonymousExposesSameResource(anonymous.Response, owner.Response) {
			continue
		}
		ownerReplay, err := r.probeAsProfileWithValue(ctx, ownerAuth, proofTarget, policy.Parameter, resourceValue)
		if err != nil || !sameResourceFingerprint(owner.Response.Body, ownerReplay.Response.Body) {
			continue
		}

		payload := defaultPayload("tenant_isolation", "declared_foreign_resource", resourceValue, "cross_tenant_access_confirmed")
		payload.SelectionReason = policy.ExpectedPolicy
		finding := r.verifyAndBuildWithCandidate(ctx, "tenant_isolation", proofTarget, payload, anonymous, foreign,
			"cross_tenant_access_confirmed", false, false, "", "", func(candidate *verification.Candidate) {
				candidate.RequestedProofType = verification.ProofIdentityBoundary
				candidate.NegativeControlSet = true
				candidate.NegativeControlOK = true
				candidate.Observations = append(candidate.Observations,
					r.identityObservation("tenant_isolation", proofTarget, verification.RoleIdentityA, 1, ownerRole.ID, owner),
					r.identityObservation("tenant_isolation", proofTarget, verification.RoleIdentityB, 1, foreignRole.ID, foreign),
					r.identityObservation("tenant_isolation", proofTarget, verification.RoleAnonymousControl, 1, "anonymous", anonymous),
					r.identityObservation("tenant_isolation", proofTarget, verification.RoleIdentityA, 2, ownerRole.ID, ownerReplay),
				)
			})
		if finding == nil {
			continue
		}
		finding.Title = "Cross-tenant isolation breach: " + foreignRole.Name + " accessed " + ownerRole.Name + " resource"
		finding.Description = policy.ExpectedPolicy + "; the declared foreign identity retrieved the owner's exact stable resource while the anonymous control was denied."
		finding.Severity = "Critical"
		var out []ModuleFinding
		r.recordFinding(ctx, &out, finding, "tenant_isolation", "cross_tenant_access_confirmed")
		return out
	}
	return nil
}
