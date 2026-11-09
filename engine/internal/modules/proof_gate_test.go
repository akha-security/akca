package modules

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/verification"
)

func TestFindingProofGateRejectsUnknownAndUnprovenClasses(t *testing.T) {
	for _, finding := range []ModuleFinding{
		{VulnClass: "unknown_future_class"},
		{VulnClass: "sqli"},
		{VulnClass: "unknown_future_class", Evidence: Evidence{Verification: verification.Result{
			ProofPolicy: verification.CurrentProofPolicyVersion, ProofSatisfied: true,
		}}},
	} {
		if findingProofEligible(finding) {
			t.Fatalf("unproven class %q passed the finding gate", finding.VulnClass)
		}
	}
}
