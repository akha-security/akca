package testlab

import "testing"

func TestRealBrowserCapabilityIsOptInOnCI(t *testing.T) {
	t.Setenv("CI", "true")
	t.Setenv("AKCA_RUN_REAL_BROWSER_TESTS", "")
	if realBrowserCapabilityAllowed(true) {
		t.Fatal("CI benchmark enabled an incidental system browser without opt-in")
	}

	t.Setenv("AKCA_RUN_REAL_BROWSER_TESTS", "1")
	if !realBrowserCapabilityAllowed(true) {
		t.Fatal("explicit CI browser integration opt-in was ignored")
	}
	if realBrowserCapabilityAllowed(false) {
		t.Fatal("disabled browser capability was enabled")
	}
}
