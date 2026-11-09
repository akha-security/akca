package verification

import (
	"fmt"
	"testing"
)

func routeProofCandidate() Candidate {
	const privateBody = `{"user_id":"customer-731","email":"owner@internal.test","secret":"private-route-canary-731"}`
	baseline := ResponseSnapshot{StatusCode: 403, Body: "access denied"}
	probe := ResponseSnapshot{StatusCode: 200, Body: privateBody}
	candidate := Candidate{
		ScanID: "route-proof", Module: "route_auth_bypass", VulnClass: "route_auth_bypass",
		EndpointURL: "https://example.test/dashboard/account", Signal: "x_original_url_header", DirectTypedSignal: true,
		ProofPolicyVersion: CurrentProofPolicyVersion, RequestedProofType: ProofDifferentialReplay,
		Baseline: baseline, Probe: probe, StabilityRuns: []ResponseSnapshot{probe, probe, probe},
		TypedReplayHits: []bool{true, true, true}, NegativeControlSet: true, NegativeControlOK: true,
	}
	add := func(role ObservationRole, attempt int, identity, rawURL string, response ResponseSnapshot) {
		item := NewHTTPObservation(candidate.ScanID, candidate.Module, candidate.EndpointURL, "", "", role, attempt, identity,
			"GET", rawURL, "", nil, response)
		item.RequestID = fmt.Sprintf("route-test-exchange-%d", proofExchangeSequence.Add(1))
		candidate.Observations = append(candidate.Observations, item)
	}
	add(RoleNativeBaseline, 1, "", candidate.EndpointURL, baseline)
	add(RoleBaselineReplay, 2, "", candidate.EndpointURL, baseline)
	add(RoleNegativeControl, 1, "", candidate.EndpointURL+"/missing", ResponseSnapshot{StatusCode: 404, Body: "not found"})
	add(RoleNegativeControl, 2, "", "https://example.test/", ResponseSnapshot{StatusCode: 200, Body: "public homepage"})
	add(RoleIdentityA, 1, "authenticated", candidate.EndpointURL, probe)
	add(RolePositiveProbe, 1, "", "https://example.test/", probe)
	add(RolePositiveReplay, 2, "", "https://example.test/", probe)
	add(RolePositiveReplay, 3, "", "https://example.test/", probe)
	return candidate
}

func TestRouteProofPolicyRequiresPrivateResourceBinding(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Candidate)
		want   bool
	}{
		{name: "authenticated reference matches", want: true},
		{name: "status change and replay alone", mutate: func(c *Candidate) { c.Observations = append(c.Observations[:4:4], c.Observations[5:]...) }},
		{name: "reference belongs to different resource", mutate: func(c *Candidate) { c.Observations[4].NormalizedHash = "unrelated-resource" }},
		{name: "reference is anonymous", mutate: func(c *Candidate) { c.Observations[4].IdentityID = "anonymous" }},
		{name: "missing negative controls", mutate: func(c *Candidate) {
			c.Observations[2].Role = RoleBaselineReplay
			c.Observations[3].Role = RoleBaselineReplay
		}},
		{name: "configured canary in all responses", want: true, mutate: func(c *Candidate) {
			c.Observations[4].IdentityID = "anonymous"
			c.PrivateResourceCanary = "private-route-canary-731"
		}},
		{name: "canary missing from replay", mutate: func(c *Candidate) {
			c.Observations[4].IdentityID = "anonymous"
			c.PrivateResourceCanary = "private-route-canary-731"
			c.StabilityRuns[2].Body = "different resource without private marker"
		}},
		{name: "public canary already in baseline", mutate: func(c *Candidate) {
			c.Observations[4].IdentityID = "anonymous"
			c.PrivateResourceCanary = "private-route-canary-731"
			c.Baseline.Body = c.Probe.Body
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := routeProofCandidate()
			if tc.mutate != nil {
				tc.mutate(&candidate)
			}
			_, satisfied := evaluateProofPolicy(candidate, Result{NegativeControlOK: true, TypedReplayRatio: 1})
			if satisfied != tc.want {
				t.Fatalf("private-resource proof satisfied=%v, want=%v", satisfied, tc.want)
			}
		})
	}
}
