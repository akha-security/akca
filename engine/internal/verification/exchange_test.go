package verification

import "testing"

func TestCopiedExchangeCannotMeetIndependentProofCount(t *testing.T) {
	a := NewHTTPObservation("s", "rate_limit", "https://example.test", "user", "query", RoleNegativeControl, 1, "", "GET", "https://example.test", "", nil, ResponseSnapshot{StatusCode: 200, Body: "ok"})
	a.RequestID = "real-request-1"
	b := a
	b.ID = "different-observation"
	b.Attempt = 2
	if got := observationRoles([]Observation{a, b})[RoleNegativeControl]; got != 1 {
		t.Fatalf("copied exchange counted %d times", got)
	}
	b.RequestID = "real-request-2"
	if got := observationRoles([]Observation{a, b})[RoleNegativeControl]; got != 2 {
		t.Fatalf("independent identical responses collapsed: %d", got)
	}
	b.RequestID = a.RequestID
	b.Role = RolePositiveProbe
	if ValidateObservations([]Observation{a, b}) {
		t.Fatal("same exchange accepted as positive and negative control")
	}
}
