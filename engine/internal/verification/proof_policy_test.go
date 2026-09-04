package verification

import (
	"testing"
	"time"

	"github.com/akha-security/akca/engine/internal/oast"
)

func proofObservation(role ObservationRole, attempt int, body string) Observation {
	return NewHTTPObservation(
		"scan-1", "sqli", "https://target.test/search", "q", "query", role, attempt, "",
		"GET", "https://target.test/search?q=x", "", nil,
		ResponseSnapshot{StatusCode: 200, Body: body, ContentType: "text/plain", DurationMs: 5},
	)
}

func TestProofPolicyRejectsSyntheticOrCopiedObservation(t *testing.T) {
	c := Candidate{
		ScanID: "scan-1", Module: "sqli", VulnClass: "sqli", EndpointURL: "https://target.test/search",
		Parameter: "q", Signal: "error_based", DirectTypedSignal: true,
		ProofPolicyVersion: CurrentProofPolicyVersion,
		Baseline:           ResponseSnapshot{StatusCode: 200, Body: "ok"},
		Probe:              ResponseSnapshot{StatusCode: 500, Body: "SQLSTATE[42000]"},
		TypedReplayHits:    []bool{true, true, true}, NegativeControlSet: true, NegativeControlOK: true,
	}
	base := proofObservation(RoleNativeBaseline, 1, "ok")
	probe := proofObservation(RolePositiveProbe, 1, "SQLSTATE[42000]")
	replay := proofObservation(RolePositiveReplay, 2, "SQLSTATE[42000]")
	c.Observations = []Observation{base, probe, replay, replay, proofObservation(RoleNegativeControl, 1, "ok")}
	result := NewEngine(nil, nil).Verify(c)
	if !result.Suppressed || result.ProofSatisfied {
		t.Fatalf("copied observation must fail closed: %+v", result)
	}
}

func TestProofPolicyAcceptsThreeRealRunsAndControl(t *testing.T) {
	c := Candidate{
		ScanID: "scan-1", Module: "sqli", VulnClass: "sqli", EndpointURL: "https://target.test/search",
		Parameter: "q", Signal: "error_based", DirectTypedSignal: true,
		ProofPolicyVersion: CurrentProofPolicyVersion,
		Baseline:           ResponseSnapshot{StatusCode: 200, Body: "ok"},
		Probe:              ResponseSnapshot{StatusCode: 500, Body: "SQLSTATE[42000]"},
		TypedReplayHits:    []bool{true, true, true}, NegativeControlSet: true, NegativeControlOK: true,
	}
	c.Observations = []Observation{
		proofObservation(RoleNativeBaseline, 1, "ok"),
		proofObservation(RolePositiveProbe, 1, "SQLSTATE[42000]"),
		proofObservation(RolePositiveReplay, 2, "SQLSTATE[42000]"),
		proofObservation(RolePositiveReplay, 3, "SQLSTATE[42000]"),
		proofObservation(RoleNegativeControl, 1, "ok"),
	}
	result := NewEngine(nil, nil).Verify(c)
	if result.Suppressed || !result.ProofSatisfied || result.ProofType != ProofDifferentialReplay {
		t.Fatalf("valid observation proof rejected: %+v", result)
	}
}

func TestObservationFailClosed(t *testing.T) {
	item := Observation{
		ID: "synthetic", ScanID: "s", Module: "sqli", Endpoint: "https://target.test",
		Role: RolePositiveProbe, Attempt: 1, StatusCode: 200, CreatedAt: time.Now(),
	}
	if item.Valid() {
		t.Fatal("observation without a real request must be rejected")
	}
}

func TestRuntimeTraceProofRequiresTypedObservation(t *testing.T) {
	candidate := Candidate{
		ScanID: "scan-1", Module: "sqli", VulnClass: "sqli", EndpointURL: "https://target.test/search",
		Parameter: "X-Forwarded-For", Signal: "runtime_sql_sink", DirectTypedSignal: true,
		ProofPolicyVersion: CurrentProofPolicyVersion, RequestedProofType: ProofRuntimeTrace,
		Baseline:           ResponseSnapshot{StatusCode: 200, Body: "same"},
		Probe:              ResponseSnapshot{StatusCode: 200, Body: "same"},
		NegativeControlSet: true, NegativeControlOK: true,
		Observations: []Observation{
			proofObservation(RoleNativeBaseline, 1, "same"),
			NewRuntimeObservation("scan-1", "sqli", "https://target.test/search", "X-Forwarded-For",
				"header", "req-1", "trace-1", "sql.query", 1, false),
		},
	}
	result := NewEngine(nil, nil).Verify(candidate)
	if result.Suppressed || !result.ProofSatisfied || result.ProofType != ProofRuntimeTrace {
		t.Fatalf("expected runtime trace proof, got %+v", result)
	}
}

func TestVersionedUnknownPolicyFailsClosed(t *testing.T) {
	candidate := Candidate{
		ScanID: "scan-1", Module: "unregistered_active_module", VulnClass: "unregistered_active_module",
		EndpointURL: "https://target.test", Signal: "typed_signal", DirectTypedSignal: true,
		ProofPolicyVersion: CurrentProofPolicyVersion, RequestedProofType: ProofContentEvidence,
		Baseline: ResponseSnapshot{StatusCode: 200, Body: "ok"},
		Probe:    ResponseSnapshot{StatusCode: 200, Body: "secret"},
		Observations: []Observation{
			NewHTTPObservation(
				"scan-1", "unregistered_active_module", "https://target.test", "q", "query",
				RolePositiveProbe, 1, "", "GET", "https://target.test?q=x", "", nil,
				ResponseSnapshot{StatusCode: 200, Body: "secret"},
			),
		},
	}
	result := NewEngine(nil, nil).Verify(candidate)
	if !result.Suppressed || result.ProofSatisfied {
		t.Fatalf("unknown versioned module must fail closed: %+v", result)
	}
}

func TestEveryProofPolicyRejectsMissingObservations(t *testing.T) {
	for module, policy := range ProofPolicyCatalog() {
		module, policy := module, policy
		t.Run(module, func(t *testing.T) {
			candidate := Candidate{
				ScanID: "scan-parity", Module: module, VulnClass: module,
				EndpointURL: "https://target.test/test", Parameter: "q",
				Signal: "typed_signal", DirectTypedSignal: true,
				ProofPolicyVersion: policy.Version, RequestedProofType: policy.AllowedProofTypes[0],
				Baseline: ResponseSnapshot{StatusCode: 200, Body: "baseline"},
				Probe:    ResponseSnapshot{StatusCode: 200, Body: "typed result"},
			}
			result := NewEngine(nil, nil).Verify(candidate)
			if !result.Suppressed || result.ProofSatisfied {
				t.Fatalf("%s accepted a versioned finding without observations: %+v", module, result)
			}
		})
	}
}

func moduleProofObservation(module string, role ObservationRole, attempt int, body string) Observation {
	return NewHTTPObservation(
		"scan-matrix", module, "https://target.test/test", "q", "query", role, attempt, "",
		"GET", "https://target.test/test?q=x", "", nil,
		ResponseSnapshot{StatusCode: 200, Body: body, ContentType: "application/json", DurationMs: 5},
	)
}

func TestPositiveProofFamilyMatrix(t *testing.T) {
	type proofFixture struct {
		module    string
		proofType ProofType
		roles     []ObservationRole
		mutate    func(*Candidate)
	}
	fixtures := []proofFixture{
		{module: "nosql", proofType: ProofDifferentialReplay,
			roles: []ObservationRole{RoleNativeBaseline, RolePositiveProbe, RolePositiveReplay, RolePositiveReplay, RoleNegativeControl}},
		{module: "xss", proofType: ProofDOMExecution,
			roles:  []ObservationRole{RoleNativeBaseline, RolePositiveProbe, RoleDOMExecution},
			mutate: func(c *Candidate) { c.DOMExecuted = true }},
		{module: "xss", proofType: ProofDifferentialReplay,
			roles: []ObservationRole{RoleNativeBaseline, RolePositiveProbe, RolePositiveReplay, RolePositiveReplay, RoleNegativeControl}},
		{module: "open_redirect", proofType: ProofHeaderEvidence,
			roles: []ObservationRole{RoleNativeBaseline, RolePositiveProbe, RolePositiveReplay, RolePositiveReplay, RoleNegativeControl}},
		{module: "secret_exposure", proofType: ProofContentEvidence,
			roles: []ObservationRole{RolePositiveProbe}},
		{module: "security_headers", proofType: ProofConfiguration,
			roles: []ObservationRole{RolePositiveProbe}},
		{module: "graphql", proofType: ProofSchemaExposure,
			roles: []ObservationRole{RolePositiveProbe, RolePositiveReplay}},
		{module: "smuggling", proofType: ProofProtocolDesync,
			roles: []ObservationRole{RoleNativeBaseline, RolePositiveProbe, RolePositiveReplay, RoleNegativeControl}},
		{module: "csrf", proofType: ProofStateMutation,
			roles: []ObservationRole{RoleNativeBaseline, RoleStateBefore, RoleStateAfter, RoleNegativeControl}},
		{module: "broken_auth", proofType: ProofAnonymousAccess,
			roles: []ObservationRole{RoleNativeBaseline, RoleIdentityA, RoleAnonymousProbe, RoleAnonymousProbe}},
		{module: "second_order", proofType: ProofStoredExecution,
			roles: []ObservationRole{RoleNativeBaseline, RolePositiveProbe}},
		{module: "idor", proofType: ProofIdentityBoundary,
			roles: []ObservationRole{RoleNativeBaseline, RoleIdentityA, RoleIdentityB, RoleAnonymousControl}},
		{module: "mass_assignment", proofType: ProofStateMutation,
			roles: []ObservationRole{RoleNativeBaseline, RoleStateBefore, RoleStateAfter, RoleNegativeControl}},
		{module: "file_upload", proofType: ProofFileRetrieval,
			roles: []ObservationRole{RoleNativeBaseline, RolePositiveProbe, RoleStateAfter, RoleNegativeControl}},
		{module: "blind_xss", proofType: ProofOAST,
			roles: []ObservationRole{RoleOASTCallback},
			mutate: func(c *Candidate) {
				c.OAST = &oast.Correlation{
					PayloadID: "payload-1", ScanID: "scan-matrix",
					EndpointURL: "https://target.test/test", VulnClass: "blind_xss",
					CallbackURL: "https://payload-1.oast.test/callback",
				}
				c.Observations = []Observation{
					NewOASTObservation(
						"scan-matrix", "blind_xss", "https://target.test/test", "q", "query",
						"payload-1", "https://payload-1.oast.test/callback", 1,
					),
				}
			}},
	}

	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.module, func(t *testing.T) {
			candidate := Candidate{
				ScanID: "scan-matrix", Module: fixture.module, VulnClass: fixture.module,
				EndpointURL: "https://target.test/test", Parameter: "q",
				Signal: "typed_signal", DirectTypedSignal: true,
				ProofPolicyVersion: CurrentProofPolicyVersion, RequestedProofType: fixture.proofType,
				Baseline:           ResponseSnapshot{StatusCode: 200, Body: `{"baseline":true}`},
				Probe:              ResponseSnapshot{StatusCode: 200, Body: `{"typed_result":true}`},
				NegativeControlSet: true, NegativeControlOK: true,
				TypedReplayHits: []bool{true, true, true},
			}
			attempts := make(map[ObservationRole]int)
			for _, role := range fixture.roles {
				attempts[role]++
				body := `{"typed_result":true}`
				if role == RoleNativeBaseline || role == RoleNegativeControl || role == RoleAnonymousControl {
					body = `{"baseline":true}`
				}
				candidate.Observations = append(candidate.Observations,
					moduleProofObservation(fixture.module, role, attempts[role], body))
			}
			if fixture.mutate != nil {
				fixture.mutate(&candidate)
			}
			result := NewEngine(nil, nil).Verify(candidate)
			if result.Suppressed || !result.ProofSatisfied || result.ProofType != fixture.proofType {
				t.Fatalf("valid %s proof rejected: %+v", fixture.proofType, result)
			}
		})
	}
}
