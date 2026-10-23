package php2shell

import "testing"

func TestInspectClassifiesBannerWithoutClaimingExploit(t *testing.T) {
	a := Inspect("https://example.test/index.php", 200, map[string]string{"X-Powered-By": "PHP/8.3.35"})
	if a.Status != "potential" || len(a.CVEs) != 2 || a.ExploitVerified {
		t.Fatalf("unexpected assessment: %+v", a)
	}
	b := Inspect("https://example.test", 200, map[string]string{"X-Powered-By": "PHP/8.3.36"})
	if b.Status != "fixed_version_observed" {
		t.Fatalf("fixed version misclassified: %+v", b)
	}
}

func TestInspectDoesNotTrustBlockedResponse(t *testing.T) {
	a := Inspect("https://example.test", 403, map[string]string{"X-Powered-By": "PHP/8.3.1"})
	if a.Status != "blocked" || len(a.Versions) != 0 {
		t.Fatalf("blocked response leaked version verdict: %+v", a)
	}
}

func TestInspectMatchesReferenceVersionVerdictRules(t *testing.T) {
	for _, tc := range []struct {
		version, status string
	}{
		{"PHP/7.4.33", "manual_review"},
		{"PHP/8.3.36-rc1", "potential"},
		{"PHP/8.3.36", "fixed_version_observed"},
	} {
		a := Inspect("https://example.test/index.php", 200, map[string]string{"X-Powered-By": tc.version})
		if a.Status != tc.status {
			t.Errorf("version %s classified as %s, want %s", tc.version, a.Status, tc.status)
		}
	}
}

func TestActiveSignalIsNotRCEProof(t *testing.T) {
	a := Inspect("http://127.0.0.1:8080/index.php", 200, nil)
	a.RecordActiveSignal(500, 1, true)
	if !a.ActiveCrashSignal || a.Status != "active_signal" || a.ExploitVerified {
		t.Fatalf("active signal incorrectly classified: %+v", a)
	}
}
