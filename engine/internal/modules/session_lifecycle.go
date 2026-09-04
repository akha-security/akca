package modules

import (
	"context"
	"strings"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/verification"
)

var logoutRouteKeywords = []string{
	"/logout", "/signout", "/sign-out", "/log-out",
	"/api/auth/logout", "/api/v1/auth/logout", "/api/auth/signout",
	"/revoke", "/api/auth/revoke", "/api/v1/logout",
}

func (r *Runner) runSessionLifecycle(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("session_lifecycle", target); !ok {
		r.emitSkip("session_lifecycle", target, reason)
		return nil
	}
	if !isLogoutRoute(strings.ToLower(strings.TrimSpace(target.EndpointURL))) {
		return nil
	}
	policy, ok := r.sessionLifecyclePolicy(target)
	if !ok {
		r.emitStatefulProofGap("session_lifecycle", target, "an explicitly disposable authentication profile and recorded protected resource are required")
		r.emitSkip("session_lifecycle", target, "an explicitly disposable authentication profile and recorded protected resource are required")
		return nil
	}
	client, profileCapable := r.client.(profiledHTTPDoer)
	anonymousClient, anonymousCapable := r.client.(sessionlessHTTPDoer)
	if !profileCapable || !anonymousCapable {
		r.emitStatefulProofGap("session_lifecycle", target, "isolated profile and anonymous requests are unavailable")
		r.emitSkip("session_lifecycle", target, "isolated profile and anonymous requests are unavailable")
		return nil
	}
	profile, ok := r.resolveAuthProfile(policy.AuthProfileID)
	if !ok {
		return nil
	}

	before, err := doRecordedAsProfile(ctx, client, profile, policy.ProtectedResource, nil)
	if err != nil || !recordedStatusOK(before.Response.StatusCode, policy.ProtectedResource.ExpectedStatuses) ||
		!privateAuthResourceEvidence(before.Response.Body) {
		return nil
	}
	anonymous, err := anonymousClient.DoWithoutSession(ctx, policy.ProtectedResource.Method,
		policy.ProtectedResource.URL, []byte(policy.ProtectedResource.Body), contentTypeHeader(policy.ProtectedResource.ContentType))
	if err != nil || anonymousExposesSameResource(anonymous.Response, before.Response) {
		return nil
	}
	logout, err := doRecordedAsProfile(ctx, client, profile, policy.Logout, nil)
	if err != nil || !recordedStatusOK(logout.Response.StatusCode, policy.Logout.ExpectedStatuses) {
		return nil
	}
	after, err := doRecordedAsProfile(ctx, client, profile, policy.ProtectedResource, nil)
	if err != nil || !sameResourceFingerprint(before.Response.Body, after.Response.Body) {
		return nil
	}
	replay, err := doRecordedAsProfile(ctx, client, profile, policy.ProtectedResource, nil)
	if err != nil || !sameResourceFingerprint(after.Response.Body, replay.Response.Body) {
		return nil
	}

	payload := defaultPayload("session_lifecycle", "disposable_session_reuse", policy.Logout.URL, "session_not_invalidated_after_logout")
	payload.SelectionReason = policy.ExpectedInvariant
	finding := r.verifyAndBuildWithCandidate(ctx, "session_lifecycle", target, payload, anonymous, after,
		"session_not_invalidated_after_logout", false, false, "", "", func(candidate *verification.Candidate) {
			candidate.RequestedProofType = verification.ProofRequestPolicy
			candidate.NegativeControlSet = true
			candidate.NegativeControlOK = true
			candidate.Observations = append(candidate.Observations,
				r.identityObservation("session_lifecycle", target, verification.RoleBaselineReplay, 1, profile.ID, before),
				r.identityObservation("session_lifecycle", target, verification.RoleNegativeControl, 1, "anonymous", anonymous),
				r.identityObservation("session_lifecycle", target, verification.RolePositiveReplay, 2, profile.ID, replay),
			)
		})
	if finding == nil {
		return nil
	}
	finding.Title = "Disposable session remained reusable after logout"
	finding.Description = policy.ExpectedInvariant + "; the protected resource remained identical across two post-logout requests while the anonymous control was denied."
	finding.Severity = "High"
	var out []ModuleFinding
	r.recordFinding(ctx, &out, finding, "session_lifecycle", "session_not_invalidated_after_logout")
	return out
}

func (r *Runner) sessionLifecyclePolicy(target ScanTarget) (config.SessionLifecycleProofPolicy, bool) {
	for _, policy := range r.cfg.SessionLifecycleProofPolicies {
		if strings.Contains(target.EndpointURL, policy.URLContains) &&
			strings.EqualFold(target.Method, policy.Logout.Method) && policy.DisposableCredential &&
			r.scope.IsInScope(policy.Logout.URL) && r.scope.IsInScope(policy.ProtectedResource.URL) {
			return policy, true
		}
	}
	return config.SessionLifecycleProofPolicy{}, false
}

func isLogoutRoute(urlLower string) bool {
	for _, keyword := range logoutRouteKeywords {
		if strings.Contains(urlLower, keyword) {
			return true
		}
	}
	return false
}
