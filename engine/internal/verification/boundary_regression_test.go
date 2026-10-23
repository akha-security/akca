package verification

import "testing"

func boundaryCandidate() Candidate {
	return Candidate{ScanID: "scan-1", Module: "sqli", VulnClass: "sqli", EndpointURL: "https://target.test/search", Parameter: "q", Location: "query", Signal: "error_based", DirectTypedSignal: true, ProofPolicyVersion: CurrentProofPolicyVersion, RequestedProofType: ProofDifferentialReplay, NegativeControlSet: true, Observations: []Observation{proofObservation(RoleNativeBaseline, 1, "ok"), proofObservation(RolePositiveProbe, 1, "SQLSTATE"), proofObservation(RolePositiveReplay, 2, "SQLSTATE"), proofObservation(RolePositiveReplay, 3, "SQLSTATE"), proofObservation(RoleNegativeControl, 1, "ok")}}
}

func TestPhysicalExchangeCannotCountAsMultipleIndependentRuns(t *testing.T) {
	c := boundaryCandidate()
	result := Result{NegativeControlOK: true}
	if _, ok := evaluateProofPolicy(c, result); !ok {
		t.Fatal("valid independent exchanges rejected")
	}
	for i := 1; i <= 3; i++ {
		c.Observations[i].RequestID = "same-exchange"
	}
	if _, ok := evaluateProofPolicy(c, result); ok {
		t.Fatal("one physical exchange counted as several runs")
	}
	for i := 1; i <= 3; i++ {
		c.Observations[i].RequestID = ""
	}
	if _, ok := evaluateProofPolicy(c, result); ok {
		t.Fatal("missing exchange IDs proved independence")
	}
}

func TestObservationMustBelongToCandidateContext(t *testing.T) {
	for _, field := range []string{"scan", "module", "endpoint", "parameter", "location"} {
		c := boundaryCandidate()
		switch field {
		case "scan":
			c.Observations[1].ScanID = "other"
		case "module":
			c.Observations[1].Module = "xss"
		case "endpoint":
			c.Observations[1].Endpoint = "https://other.test"
		case "parameter":
			c.Observations[1].Parameter = "other"
		case "location":
			c.Observations[1].Location = "header"
		}
		if _, ok := evaluateProofPolicy(c, Result{NegativeControlOK: true}); ok {
			t.Fatalf("foreign %s accepted", field)
		}
	}
	c := boundaryCandidate()
	c.Observations[len(c.Observations)-1].RequestURL = "https://target.test/control-route"
	if _, ok := evaluateProofPolicy(c, Result{NegativeControlOK: true}); !ok {
		t.Fatal("logical-target-bound negative URL incorrectly rejected")
	}
}

func TestStateRequirementAppliesToDifferentialReplay(t *testing.T) {
	c := boundaryCandidate()
	c.Module = "mass_assignment"
	c.VulnClass = c.Module
	for i := range c.Observations {
		c.Observations[i].Module = c.Module
	}
	if _, ok := evaluateProofPolicy(c, Result{NegativeControlOK: true}); ok {
		t.Fatal("state policy accepted replay without before/after")
	}
	for _, role := range []ObservationRole{RoleStateBefore, RoleStateAfter} {
		o := proofObservation(role, 1, "state")
		o.Module = c.Module
		c.Observations = append(c.Observations, o)
	}
	if _, ok := evaluateProofPolicy(c, Result{NegativeControlOK: true}); !ok {
		t.Fatal("state-backed differential proof rejected")
	}
}

func TestSuppressionConfidenceAndFlagStayConsistent(t *testing.T) {
	result := NewEngine(nil, nil).finalize(Candidate{}, Result{Confidence: Suppressed, Score: .9, ProofSatisfied: true})
	if !result.Suppressed || result.Score != 0 {
		t.Fatalf("inconsistent suppression: %+v", result)
	}
}
