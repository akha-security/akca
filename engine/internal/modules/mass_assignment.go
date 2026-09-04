package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/akha-security/akca/engine/internal/safemutation"
	"github.com/akha-security/akca/engine/internal/verification"
)

func (r *Runner) runMassAssignment(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("mass_assignment", target); !ok {
		r.emitSkip("mass_assignment", target, reason)
		return nil
	}
	location := strings.ToLower(strings.TrimSpace(target.Location + " " + target.Profile.ParameterLocation))
	method := strings.ToUpper(strings.TrimSpace(target.Method))
	if !strings.Contains(location, "json") || (method != http.MethodPut && method != http.MethodPatch) {
		if method == http.MethodPost {
			r.emitStatefulProofGap("mass_assignment", target, "POST creation cannot be safely restored by replaying the original request; use a recorded cleanup policy")
			r.emitSkip("mass_assignment", target, "POST creation cannot be safely restored by replaying the original request; use a recorded cleanup policy")
		}
		return nil
	}
	var original map[string]interface{}
	if strings.TrimSpace(target.BodyTemplate) == "" || json.Unmarshal([]byte(target.BodyTemplate), &original) != nil || len(original) == 0 {
		r.emitStatefulProofGap("mass_assignment", target, "active mutation disabled: a restorable JSON body template is required")
		r.emitSkip("mass_assignment", target, "active mutation disabled: a restorable JSON body template is required")
		return nil
	}
	// Only mutate privilege fields already present in the captured request. An
	// original value is required so the exact request can be replayed as cleanup.
	privilegeValues := map[string]interface{}{
		"is_admin": true, "role": "admin", "roles": []string{"admin"}, "admin": true,
		"verified": true, "is_verified": true, "discount_percent": 100,
		"role_id": 1, "user_role": "superuser", "superadmin": true, "account_type": "admin",
		"email_verified": true, "active": true, "status": "active",
	}
	stateTarget := target
	stateTarget.Method = http.MethodGet
	stateTarget.Parameter = ""
	stateTarget.Location = ""
	before, err := r.probeWithoutInjectedPayload(ctx, "mass_assignment", stateTarget)
	if err != nil || before.Response.StatusCode < 200 || before.Response.StatusCode >= 300 {
		r.emitStatefulProofGap("mass_assignment", target, "state snapshot GET is unavailable")
		r.emitSkip("mass_assignment", target, "state snapshot GET is unavailable")
		return nil
	}
	var out []ModuleFinding

	for key, privilegedValue := range privilegeValues {
		if _, restorable := original[key]; !restorable || ctx.Err() != nil {
			continue
		}
		injected := make(map[string]interface{}, len(original))
		for field, value := range original {
			injected[field] = value
		}
		injected[key] = privilegedValue
		injectedBytes, _ := json.Marshal(injected)
		tx, beginErr := r.safeMutationGuard().Begin(safemutation.Operation{
			ID: "mass-assignment-" + key, Risk: safemutation.ReversibleWrite,
			ResourceID: target.EndpointURL, CleanupDefined: true,
		}, resourceFingerprint(before.Response.Body))
		if beginErr != nil {
			continue
		}
		mutationRR, mutationErr := r.probeWithBodyForModule(ctx, "mass_assignment", target, string(injectedBytes), "application/json", nil)
		after, afterErr := r.probeWithoutInjectedPayload(ctx, "mass_assignment", stateTarget)
		_, cleanupErr := r.probeWithBodyForModule(ctx, "mass_assignment", target, target.BodyTemplate, "application/json", nil)
		afterCleanup, cleanupStateErr := r.probeWithoutInjectedPayload(ctx, "mass_assignment", stateTarget)
		cleanupComplete := cleanupErr == nil && cleanupStateErr == nil &&
			resourceFingerprint(afterCleanup.Response.Body) == resourceFingerprint(before.Response.Body)
		_, finishErr := r.safeMutationGuard().Finish(tx.ID, resourceFingerprint(after.Response.Body), cleanupComplete)
		if mutationErr != nil || afterErr != nil || finishErr != nil || mutationRR.Response.StatusCode >= 400 ||
			resourceFingerprint(after.Response.Body) == resourceFingerprint(before.Response.Body) {
			continue
		}
		signal := "mass_assignment_" + key
		p := defaultPayload("mass_assignment", key, string(injectedBytes), signal)
		f := r.verifyAndBuildWithCandidate(ctx, "mass_assignment", target, p, before, after, signal, false, false, "", "", func(candidate *verification.Candidate) {
			candidate.RequestedProofType = verification.ProofStateMutation
			candidate.NegativeControlSet = true
			candidate.NegativeControlOK = cleanupComplete
			candidate.Observations = append(candidate.Observations,
				r.observation("mass_assignment", target, verification.RoleStateBefore, 1, before),
				r.observation("mass_assignment", target, verification.RoleStateAfter, 1, after),
				r.observation("mass_assignment", target, verification.RoleNegativeControl, 1, afterCleanup))
		})
		if f != nil {
			f.Title = fmt.Sprintf("JSON Mass Assignment / Privilege Escalation (%s)", key)
			f.Severity = "critical"
			f.Description = fmt.Sprintf("The endpoint persisted the privileged '%s' value. The original JSON request was replayed and an independent GET confirmed complete state restoration.", key)
			r.recordFinding(ctx, &out, f, "mass_assignment", signal)
			return out
		}
	}
	return nil
}

func buildInjectedJSONBody(paramName, bodyTemplate, key string, val interface{}) string {
	m := map[string]interface{}{}
	if strings.TrimSpace(bodyTemplate) != "" {
		_ = json.Unmarshal([]byte(bodyTemplate), &m)
	}
	if len(m) == 0 {
		if paramName != "" && paramName != "body" {
			m[paramName] = "akca_test"
		} else {
			m["name"] = "akca_test"
		}
	}
	m[key] = val
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Sprintf(`{"%s": "akca_test", "%s": true}`, paramName, key)
	}
	return string(b)
}

func massAssignmentSignal(body, baseline, payload string) bool {
	lowerBody := strings.ToLower(body)
	lowerBase := strings.ToLower(baseline)
	if lowerBody == lowerBase {
		return false
	}
	if strings.Contains(lowerBody, `"received"`) || strings.Contains(lowerBody, `"echo"`) || strings.Contains(lowerBody, `"request"`) {
		return false
	}
	return (strings.Contains(lowerBody, `"role":"admin"`) && !strings.Contains(lowerBase, `"role":"admin"`)) ||
		(strings.Contains(lowerBody, `"is_admin":true`) && !strings.Contains(lowerBase, `"is_admin":true`)) ||
		(strings.Contains(lowerBody, `"admin":true`) && !strings.Contains(lowerBase, `"admin":true`))
}
