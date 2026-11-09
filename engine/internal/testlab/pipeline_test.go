package testlab

import "testing"

func TestRealBrowserCapabilityRequiresExplicitOptIn(t *testing.T) {
	for _, ciValue := range []string{"", "true"} {
		t.Setenv("CI", ciValue)
		t.Setenv("AKCA_RUN_REAL_BROWSER_TESTS", "")
		if realBrowserCapabilityAllowed(true) {
			t.Fatalf("incidental system browser was enabled without opt-in (CI=%q)", ciValue)
		}
		t.Setenv("AKCA_RUN_REAL_BROWSER_TESTS", "1")
		if !realBrowserCapabilityAllowed(true) {
			t.Fatalf("explicit browser integration opt-in was ignored (CI=%q)", ciValue)
		}
		if realBrowserCapabilityAllowed(false) {
			t.Fatal("disabled browser capability was enabled")
		}
	}
}
