package modules

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/safemutation"
	"github.com/akha-security/akca/engine/internal/verification"
)

func (r *Runner) runMassAssignment(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("mass_assignment", target); !ok {
		r.emitSkip("mass_assignment", target, reason)
		return nil
	}
	original := strings.TrimSpace(target.BodyTemplate)
	var originalObject map[string]interface{}
	if original == "" || json.Unmarshal([]byte(original), &originalObject) != nil {
		r.emitSkip("mass_assignment", target, "state proof requires a recorded JSON request template")
		return nil
	}
	before, err := r.client.Do(ctx, http.MethodGet, target.EndpointURL, nil, r.wafHeaders(target.EndpointURL))
	if err != nil || before.Response.StatusCode < 200 || before.Response.StatusCode >= 300 {
		return nil
	}
	guard := r.safeMutationGuard()
	tx, err := guard.Begin(safemutation.Operation{
		ID: "mass_assignment:" + target.EndpointURL, ResourceID: target.EndpointURL,
		Risk: safemutation.ReversibleWrite, CleanupDefined: true,
	}, resourceFingerprint(before.Response.Body))
	if err != nil {
		return nil
	}
	probes := []struct {
		field  string
		value  interface{}
		signal string
	}{
		{"role", "admin", "role_escalation"},
		{"is_admin", true, "hidden_admin_flag"},
		{"permissions", []interface{}{"*"}, "permission_injection"},
	}
	restore := func() (httpclient.RequestResponse, bool) {
		if _, restoreErr := r.probeWithBody(ctx, target, original, "application/json",
			map[string]string{"X-Akca-Canary": tx.Canary}); restoreErr != nil {
			return httpclient.RequestResponse{}, false
		}
		cleanup, cleanupErr := r.client.Do(ctx, http.MethodGet, target.EndpointURL, nil, r.wafHeaders(target.EndpointURL))
		return cleanup, cleanupErr == nil && sameResourceFingerprint(before.Response.Body, cleanup.Response.Body)
	}
	// A generic DAST must not repeatedly alter the same production object.
	// Test only the highest-priority privilege field unless the user supplies a
	// clone-per-probe workflow.
	for _, probe := range probes[:1] {
		mutated := cloneJSONObject(originalObject)
		mutated[probe.field] = probe.value
		raw, _ := json.Marshal(mutated)
		write, err := r.probeWithBody(ctx, target, string(raw), "application/json",
			map[string]string{"X-Akca-Canary": tx.Canary})
		if err != nil || write.Response.StatusCode < 200 || write.Response.StatusCode >= 300 {
			_, cleanupOK := restore()
			_, _ = guard.Finish(tx.ID, "", cleanupOK)
			return nil
		}
		after, err := r.client.Do(ctx, http.MethodGet, target.EndpointURL, nil, r.wafHeaders(target.EndpointURL))
		if err != nil || !jsonContainsExactValue(after.Response.Body, probe.field, probe.value) ||
			jsonContainsExactValue(before.Response.Body, probe.field, probe.value) {
			_, cleanupOK := restore()
			_, _ = guard.Finish(tx.ID, "", cleanupOK)
			return nil
		}
		// Restore the recorded native object and independently verify cleanup
		// before emitting a finding.
		cleanup, cleanupOK := restore()
		if _, finishErr := guard.Finish(tx.ID, resourceFingerprint(after.Response.Body), cleanupOK); finishErr != nil {
			return nil
		}
		payload := defaultPayload("mass_assignment", probe.signal, string(raw), probe.signal)
		finding := r.verifyAndBuildWithCandidate(ctx, "mass_assignment", target, payload, before, after,
			probe.signal, false, false, "", "", func(candidate *verification.Candidate) {
				candidate.RequestedProofType = verification.ProofStateMutation
				candidate.NegativeControlSet = true
				candidate.NegativeControlOK = true
				candidate.Observations = append(candidate.Observations,
					r.observation("mass_assignment", target, verification.RoleStateBefore, 1, before),
					r.observation("mass_assignment", target, verification.RoleStateAfter, 1, after),
					r.observation("mass_assignment", target, verification.RoleNegativeControl, 1, cleanup),
				)
			})
		if finding == nil {
			return nil
		}
		finding.Description = "A privilege field persisted in a clean GET after the write; the original state was then restored and verified."
		var out []ModuleFinding
		r.recordFinding(&out, finding, "mass_assignment", probe.signal)
		return out
	}
	return nil
}

func cloneJSONObject(source map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(source)+1)
	for key, value := range source {
		out[key] = value
	}
	return out
}

func jsonContainsExactValue(body, field string, expected interface{}) bool {
	var value interface{}
	if json.Unmarshal([]byte(body), &value) != nil {
		return false
	}
	return findJSONField(value, field, expected)
}

func findJSONField(value interface{}, field string, expected interface{}) bool {
	switch typed := value.(type) {
	case map[string]interface{}:
		for key, child := range typed {
			if key == field && massJSONValuesEqual(child, expected) {
				return true
			}
			if findJSONField(child, field, expected) {
				return true
			}
		}
	case []interface{}:
		for _, child := range typed {
			if findJSONField(child, field, expected) {
				return true
			}
		}
	}
	return false
}

func massJSONValuesEqual(a, b interface{}) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return string(left) == string(right)
}

func massAssignmentSignal(body, baseline, payload string) bool {
	if payloadSemanticallyReflected(payload, body) {
		return false
	}
	return privilegeEscalationSignal(body, baseline)
}
