package modules

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/reflection"
	"github.com/akha-security/akca/engine/internal/verification"
)

// RoleComparer remains available for UI-only role comparisons. Security
// findings use the request-level ownership proof below.
type RoleComparer interface {
	CompareRoles(ctx context.Context, url string, roleA, roleB config.AuthProfile) (RoleComparisonResult, error)
}

type AuthProfileResolver interface {
	ResolveProfile(profileID string) (config.AuthProfile, bool)
}

type RoleComparisonResult struct {
	RoleA         string
	RoleB         string
	StatusA       int
	StatusB       int
	AccessControl string
	Notes         string
}

func (r *Runner) resolveAuthProfile(profileID string) (config.AuthProfile, bool) {
	for _, p := range r.cfg.AuthProfiles {
		if p.ID == profileID {
			return p, true
		}
	}
	if r.authResolve != nil {
		return r.authResolve.ResolveProfile(profileID)
	}
	return config.AuthProfile{}, false
}

func (r *Runner) runIDORRoleCompare(ctx context.Context, target ScanTarget) []ModuleFinding {
	policy, ok := r.bolaPolicy(target)
	if !ok {
		return nil
	}
	client, anonymousCapable := r.client.(sessionlessHTTPDoer)
	if !anonymousCapable {
		r.emitSkip("idor", target, "anonymous authorization control unavailable")
		return nil
	}
	ownerRole, roleA, okA := r.resolveRoleProfile(policy.OwnerRoleProfileID)
	foreignRole, roleB, okB := r.resolveRoleProfile(policy.ForeignRoleProfileID)
	if !okA || !okB {
		return nil
	}
	parameter := policy.Parameter
	location := policy.Location
	if location == "" {
		location = target.Location
	}
	proofTarget := target
	proofTarget.Parameter = parameter
	proofTarget.Location = location
	for _, resourceValue := range policy.ResourceValues {
		resource := IDCandidate{Name: parameter, Value: resourceValue, Kind: "declared_owner_resource"}
		owner, err := r.probeAsProfileWithValue(ctx, roleA, proofTarget, resource.Name, resource.Value)
		if err != nil || !successfulResourceResponse(owner.Response) {
			continue
		}
		foreign, err := r.probeAsProfileWithValue(ctx, roleB, proofTarget, resource.Name, resource.Value)
		if err != nil || !successfulResourceResponse(foreign.Response) ||
			!sameResourceFingerprint(owner.Response.Body, foreign.Response.Body) {
			continue
		}
		anonymousURL, anonymousBody, anonymousHeaders, err := buildAuthorizationRequest(proofTarget, resource.Name, resource.Value)
		if err != nil {
			continue
		}
		anonymous, err := client.DoWithoutSession(ctx, effectiveMethod(target.Method, target.Location),
			anonymousURL, anonymousBody, anonymousHeaders)
		if err != nil || anonymousExposesSameResource(anonymous.Response, owner.Response) {
			continue
		}
		ownerAfter, err := r.probeAsProfileWithValue(ctx, roleA, proofTarget, resource.Name, resource.Value)
		if err != nil || !sameResourceFingerprint(owner.Response.Body, ownerAfter.Response.Body) {
			continue
		}
		payload := defaultPayload("idor", "foreign_object_access", resource.Value, "foreign_object_access")
		payload.SelectionReason = policy.ExpectedPolicy
		finding := r.verifyAndBuildWithCandidate(ctx, "idor", proofTarget, payload, anonymous, foreign,
			"foreign_object_access", false, false, "", "", func(candidate *verification.Candidate) {
				candidate.RequestedProofType = verification.ProofIdentityBoundary
				candidate.NegativeControlSet = true
				candidate.NegativeControlOK = true
				candidate.Observations = append(candidate.Observations,
					r.identityObservation("idor", proofTarget, verification.RoleIdentityA, 1, roleA.ID, owner),
					r.identityObservation("idor", proofTarget, verification.RoleIdentityB, 1, roleB.ID, foreign),
					r.identityObservation("idor", proofTarget, verification.RoleAnonymousControl, 1, "anonymous", anonymous),
					r.identityObservation("idor", proofTarget, verification.RoleIdentityA, 2, roleA.ID, ownerAfter),
				)
			})
		if finding == nil {
			continue
		}
		finding.Title = "IDOR/BOLA: " + foreignRole.Name + " accessed " + ownerRole.Name + " resource"
		finding.Description = "The declared foreign identity retrieved the owner's exact stable resource while the anonymous control was denied."
		var out []ModuleFinding
		r.recordFinding(ctx, &out, finding, "idor", "foreign_object_access")
		return out
	}
	return nil
}

func (r *Runner) resolveRoleProfile(roleID string) (config.RoleProfile, config.AuthProfile, bool) {
	for _, role := range r.cfg.RoleProfiles {
		if role.ID != roleID {
			continue
		}
		auth, ok := r.resolveAuthProfile(role.AuthProfileID)
		return role, auth, ok
	}
	return config.RoleProfile{}, config.AuthProfile{}, false
}

func (r *Runner) bolaPolicy(target ScanTarget) (config.ObjectAuthorizationPolicy, bool) {
	method := strings.ToUpper(strings.TrimSpace(target.Method))
	if method == "" {
		method = "GET"
	}
	for _, policy := range r.cfg.ObjectAuthorizationPolicies {
		if !strings.Contains(target.EndpointURL, policy.URLContains) ||
			!strings.EqualFold(method, policy.Method) ||
			len(policy.ResourceValues) == 0 || !policy.RequireAnonymousDeny {
			continue
		}
		return policy, true
	}
	return config.ObjectAuthorizationPolicy{}, false
}

func buildAuthorizationRequest(target ScanTarget, parameter, value string) (string, []byte, map[string]string, error) {
	location := target.Location
	if location == "" {
		location = target.Profile.ParameterLocation
	}
	return buildProbeRequestForAuthorization(target.EndpointURL, target.Method, parameter, location, value)
}

func buildProbeRequestForAuthorization(endpoint, method, parameter, location, value string) (string, []byte, map[string]string, error) {
	return reflectionBuildProbeRequest(endpoint, method, parameter, location, value)
}

// Kept behind a variable so authorization tests can exercise request
// construction without replacing the scanner's reflection package.
var reflectionBuildProbeRequest = func(endpoint, method, parameter, location, value string) (string, []byte, map[string]string, error) {
	return reflection.BuildProbeRequest(endpoint, method, parameter, location, value)
}

func (r *Runner) identityObservation(module string, target ScanTarget, role verification.ObservationRole,
	attempt int, identity string, rr httpclient.RequestResponse) verification.Observation {
	item := r.observation(module, target, role, attempt, rr)
	item.IdentityID = identity
	return item
}

func successfulResourceResponse(response httpclient.ResponseRecord) bool {
	return response.StatusCode >= 200 && response.StatusCode < 300 &&
		len(strings.TrimSpace(response.Body)) > 2 && !authDeniedBody(strings.ToLower(response.Body))
}

func anonymousExposesSameResource(anonymous, owner httpclient.ResponseRecord) bool {
	return successfulResourceResponse(anonymous) && sameResourceFingerprint(anonymous.Body, owner.Body)
}

func sameResourceFingerprint(a, b string) bool {
	if strings.TrimSpace(a) == "" || strings.TrimSpace(b) == "" {
		return false
	}
	return resourceFingerprint(a) == resourceFingerprint(b)
}

func resourceFingerprint(body string) string {
	var value interface{}
	if json.Unmarshal([]byte(body), &value) == nil {
		raw, _ := json.Marshal(value)
		body = string(raw)
	}
	body = normalizeVolatileFields(body)
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}
