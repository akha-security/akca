package report

import "github.com/akha-security/akca/engine/internal/verification"

// storedProofEligible validates the part of a module's proof that a report can
// check without sending new requests. Runtime verification remains the source
// of the actual proof decision.
func storedProofEligible(vulnClass string, evidence HTTPEvidence) bool {
	if !evidence.ProofSatisfied || evidence.ProofPolicy != verification.CurrentProofPolicyVersion ||
		len(evidence.Observations) == 0 {
		return false
	}
	policy, ok := verification.ProofPolicy(vulnClass)
	if !ok || policy.Version != evidence.ProofPolicy {
		return false
	}
	for _, allowed := range policy.AllowedProofTypes {
		if string(allowed) == evidence.ProofType {
			return true
		}
	}
	return false
}
