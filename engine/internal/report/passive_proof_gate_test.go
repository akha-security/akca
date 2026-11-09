package report

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/storage"
)

func TestPassiveClassAndSignalDoNotManufactureProof(t *testing.T) {
	for _, tc := range []struct{ class, signal string }{
		{"secret_exposure", "passive_secret"},
		{"security_headers", "missing_content_security_policy"},
		{"sqli", "passive_sqli"},
	} {
		rec := storage.FindingRecord{
			Title: "Unverified", VulnClass: tc.class,
			Confidence: "Confirmed", ConfidenceScore: 0.95,
			EvidenceJSON: `{"module":"` + tc.class + `","signal":"` + tc.signal + `","request":{"method":"GET","url":"https://example.test/"}}`,
		}
		entry := FindingFromRecord(rec, false)
		if entry.HTTPEvidence.ProofSatisfied || reportableFinding(entry, TemplateInternal) {
			t.Fatalf("%s/%s became a proven finding without proof", tc.class, tc.signal)
		}
	}
}

func TestStoredProofRequiresCurrentClassPolicyAndObservation(t *testing.T) {
	valid := HTTPEvidence{ProofSatisfied: true, ProofPolicy: "3.2", ProofType: "boolean_pair",
		Observations: []storage.VerificationObservationRecord{{ID: "proof", Role: "positive_probe"}}}
	if !storedProofEligible("sqli", valid) {
		t.Fatal("current class-specific proof was rejected")
	}
	for _, tc := range []struct {
		name     string
		class    string
		evidence HTTPEvidence
	}{
		{"wrong class", "xss", valid},
		{"unknown class", "unknown_class", valid},
		{"stale policy", "sqli", HTTPEvidence{ProofSatisfied: true, ProofPolicy: "3.0", ProofType: "boolean_pair", Observations: valid.Observations}},
		{"no observation", "sqli", HTTPEvidence{ProofSatisfied: true, ProofPolicy: "3.2", ProofType: "boolean_pair"}},
	} {
		if storedProofEligible(tc.class, tc.evidence) {
			t.Fatalf("%s passed the stored proof gate", tc.name)
		}
	}
}
