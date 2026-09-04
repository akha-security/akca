package verification

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/oast"
	"github.com/akha-security/akca/engine/internal/reflection"
	"github.com/akha-security/akca/engine/internal/storage"
)

func TestConfidenceTiers(t *testing.T) {
	engine := NewEngine(nil, nil)
	confirmed := engine.Verify(Candidate{
		ScanID: "s1", Title: "xss", VulnClass: "xss", EndpointURL: "http://x.test",
		Baseline:        ResponseSnapshot{StatusCode: 200, Body: "ok"},
		Probe:           ResponseSnapshot{StatusCode: 200, Body: `<script>alert(1)</script>`, ContentType: "text/html"},
		PolymorphicHits: []bool{true, true, false},
		StabilityRuns:   repeatProbe(`<script>alert(1)</script>`, 5),
		OAST: &oast.Correlation{PayloadID: "pl-1", ScanID: "s1", EndpointURL: "http://x.test",
			VulnClass: "xss", CallbackURL: "https://pl-1.oast.test/"},
		DOMExecuted: true,
	})
	if confirmed.Confidence != Confirmed {
		t.Fatalf("expected Confirmed, got %s", confirmed.Confidence)
	}

	high := engine.Verify(Candidate{
		ScanID: "s1", Title: "sqli", VulnClass: "sqli",
		Baseline:        ResponseSnapshot{StatusCode: 200, Body: "items"},
		Probe:           ResponseSnapshot{StatusCode: 500, Body: "mysql syntax error near", ContentType: "text/html"},
		PolymorphicHits: []bool{true, true},
		StabilityRuns:   repeatProbe("mysql syntax error near", 5),
	})
	if high.Confidence != NeedsManualReview {
		t.Fatalf("untyped error-page difference must remain manual review, got %s", high.Confidence)
	}

	potential := engine.Verify(Candidate{
		ScanID: "s1", Title: "xss", VulnClass: "xss",
		Baseline:   ResponseSnapshot{StatusCode: 200, Body: "ok"},
		Probe:      ResponseSnapshot{StatusCode: 200, Body: "reflected payload", ContentType: "text/html"},
		DOMPresent: true,
	})
	if potential.Confidence != Potential && potential.Confidence != NeedsManualReview {
		t.Fatalf("expected potential/manual, got %s", potential.Confidence)
	}
}

func TestWAFBlockPageSuppression(t *testing.T) {
	r := NewEngine(nil, nil).Verify(Candidate{
		ScanID: "s1", Title: "sqli", VulnClass: "sqli",
		Baseline: ResponseSnapshot{Body: "ok"},
		Probe:    ResponseSnapshot{StatusCode: 403, Body: "Attention Required! Ray ID abc"},
	})
	if r.Confidence != Suppressed {
		t.Fatalf("expected suppressed WAF block, got %s", r.Confidence)
	}
}

func TestGenericErrorSuppression(t *testing.T) {
	r := NewEngine(nil, nil).Verify(Candidate{
		ScanID: "s1", Baseline: ResponseSnapshot{Body: "ok"},
		Probe: ResponseSnapshot{StatusCode: 500, Body: "500 Internal Server Error"},
	})
	for _, reason := range r.DowngradeReasons {
		if reason == ReasonGenericErrorPage {
			return
		}
	}
	t.Fatal("expected generic error downgrade")
}

func TestSoft404Suppression(t *testing.T) {
	base := ResponseSnapshot{StatusCode: 200, Body: "same content body"}
	probe := ResponseSnapshot{StatusCode: 200, Body: "same content body"}
	r := NewEngine(nil, nil).Verify(Candidate{ScanID: "s1", Baseline: base, Probe: probe})
	for _, reason := range r.DowngradeReasons {
		if reason == ReasonSoft404 {
			return
		}
	}
	t.Fatal("expected soft404 downgrade")
}

func TestSafeTextContainerDowngrade(t *testing.T) {
	r := NewEngine(nil, nil).Verify(Candidate{
		ScanID:    "s1",
		VulnClass: "xss",
		Baseline:  ResponseSnapshot{StatusCode: 200, Body: "hello", ContentType: "text/html"},
		Probe:     ResponseSnapshot{StatusCode: 200, Body: "hello canary", ContentType: "text/html"},
		Reflection: &reflection.ReflectionProfile{
			Context: reflection.ContextHTML, ReflectionKind: reflection.ReflectionRaw,
		},
	})
	for _, reason := range r.DowngradeReasons {
		if reason == ReasonSafeTextContainer || reason == ReasonBaselineMatch {
			return
		}
	}
	t.Fatal("expected safe container downgrade")
}

func TestStabilityWindowThresholds(t *testing.T) {
	_, level, suppress := EvaluateStability([]bool{true, true, true, true, false})
	if level != HighConfidence || suppress {
		t.Fatalf("80%% should be high confidence")
	}
	_, level, suppress = EvaluateStability([]bool{true, true, true, false, false})
	if level != NeedsManualReview || suppress {
		t.Fatalf("60%% should be manual review")
	}
	_, _, suppress = EvaluateStability([]bool{true, false, false, false, false})
	if !suppress {
		t.Fatal("<50%% should suppress")
	}
}

func TestPolymorphicConfirmation(t *testing.T) {
	if !ConfirmPolymorphic([]bool{true, true, false}) {
		t.Fatal("expected polymorphic confirmation with 2/3")
	}
	if ConfirmPolymorphic([]bool{true, false, false}) {
		t.Fatal("expected polymorphic failure with 1/3")
	}
	variants := PolymorphicVariants("xss", `<script>alert(1)</script>`)
	if len(variants) < 3 {
		t.Fatal("expected 3 xss variants")
	}
}

func TestSemanticComparison(t *testing.T) {
	base := ResponseSnapshot{ContentType: "application/json", Body: `{"a":1,"b":2}`}
	probe := ResponseSnapshot{ContentType: "application/json", Body: `{"a":9,"b":2,"c":3}`}
	if !SemanticDiffers(base, probe) {
		t.Fatal("json key structure change should differ")
	}
}

func TestPlainBodyInequalityIsNotSemanticEvidence(t *testing.T) {
	base := ResponseSnapshot{StatusCode: 200, ContentType: "text/plain", Body: "request id one"}
	probe := ResponseSnapshot{StatusCode: 200, ContentType: "text/plain", Body: "request id two"}
	if SemanticDiffers(base, probe) {
		t.Fatal("arbitrary plain-text inequality must not receive semantic evidence")
	}
}

func TestSSRFRequiresClassSpecificProof(t *testing.T) {
	result := NewEngine(nil, nil).Verify(Candidate{
		ScanID: "s1", Module: "ssrf", VulnClass: "ssrf", Signal: "aws_metadata",
		EndpointURL: "https://target.test/fetch",
		Baseline:    ResponseSnapshot{StatusCode: 200, Body: "ok"},
		Probe:       ResponseSnapshot{StatusCode: 200, Body: "different body"},
	})
	if !result.Suppressed || !hasReason(result, ReasonInsufficientProof) {
		t.Fatalf("generic body difference cannot prove SSRF: %+v", result)
	}
}

func TestParameterEndpointBaseline(t *testing.T) {
	key := BaselineKey{EndpointURL: "http://x.test", Method: "GET", Parameter: "id"}
	base := ResponseSnapshot{StatusCode: 200, Body: "baseline"}
	probe := ResponseSnapshot{StatusCode: 200, Body: "changed"}
	if CompareParameterBaseline(base, probe) {
		t.Fatal("parameter baseline should detect change")
	}
	_ = FingerprintBaseline(key, base, "x.test")
}

func TestBaselineAndSemanticComparisonIgnoreVolatileFields(t *testing.T) {
	base := ResponseSnapshot{
		StatusCode:  200,
		ContentType: "application/json",
		Body:        `{"created_at":"2026-07-24T10:00:00Z","request_id":"550e8400-e29b-41d4-a716-446655440000","csrf_token":"abcdefghijklmnop1234","value":"same"}`,
	}
	probe := ResponseSnapshot{
		StatusCode:  200,
		ContentType: "application/json",
		Body:        `{"created_at":"2026-07-24T10:00:01Z","request_id":"123e4567-e89b-12d3-a456-426614174000","csrf_token":"zyxwvutsrqponmlk9876","value":"same"}`,
	}
	if !CompareParameterBaseline(base, probe) {
		t.Fatal("volatile-only changes should match the parameter baseline")
	}
	if SemanticDiffers(base, probe) {
		t.Fatal("volatile-only changes should not receive a semantic-diff bonus")
	}
}

func TestTimingJitterCalibration(t *testing.T) {
	_, sig := CalibrateTiming([]int64{900, 920, 880, 910, 905}, []int64{100, 110, 95, 105, 100})
	if !sig {
		t.Fatal("expected significant timing delta")
	}
	_, sig = CalibrateTiming([]int64{120, 400, 90, 300, 110}, []int64{100, 105, 95, 100, 98})
	if sig {
		t.Fatal("high jitter should not be significant")
	}
}

func TestTimingRequiresThreeConsistentProbeSamples(t *testing.T) {
	if _, sig := CalibrateTiming([]int64{5100, 5120}, []int64{100, 110, 105, 98, 102}); sig {
		t.Fatal("two slow requests must not establish a timing vulnerability")
	}
	if _, sig := CalibrateTiming([]int64{105, 115, 5100}, []int64{100, 110, 105, 98, 102}); sig {
		t.Fatal("one latency outlier must not establish a timing vulnerability")
	}
	r := NewEngine(nil, nil).Verify(Candidate{
		ScanID: "s1", Module: "sqli", VulnClass: "sqli", Signal: "timing_differential",
		EndpointURL: "http://x.test/items", Baseline: ResponseSnapshot{Body: "ok"},
		Probe: ResponseSnapshot{Body: "slow"}, TimingSamples: []int64{5100, 5120},
		TimingControl: []int64{100, 110, 105, 98, 102},
	})
	if !r.Suppressed || !hasReason(r, ReasonTimingSamples) {
		t.Fatalf("insufficient timing evidence must be suppressed: %+v", r)
	}
}

func TestTypedReplayAndNegativeControlGate(t *testing.T) {
	base := Candidate{
		ScanID: "s1", Module: "sqli", VulnClass: "sqli", Signal: "error_based",
		EndpointURL: "http://x.test/items", Baseline: ResponseSnapshot{StatusCode: 200, Body: "items"},
		Probe:              ResponseSnapshot{StatusCode: 500, Body: "SQL syntax error"},
		NegativeControlSet: true, NegativeControlOK: true,
	}
	unstable := base
	unstable.TypedReplayHits = []bool{true, false, false}
	if r := NewEngine(nil, nil).Verify(unstable); !r.Suppressed || !hasReason(r, ReasonTypedReplayFailed) {
		t.Fatalf("typed replay failure must suppress injection finding: %+v", r)
	}
	controlHit := base
	controlHit.TypedReplayHits = []bool{true, true, true}
	controlHit.NegativeControlOK = false
	if r := NewEngine(nil, nil).Verify(controlHit); !r.Suppressed || !hasReason(r, ReasonNegativeControlHit) {
		t.Fatalf("negative control hit must suppress injection finding: %+v", r)
	}
	confirmed := base
	confirmed.TypedReplayHits = []bool{true, true, true}
	if r := NewEngine(nil, nil).Verify(confirmed); r.Suppressed || r.Score < 0.80 {
		t.Fatalf("stable typed proof with clean control should survive: %+v", r)
	}
}

func TestBooleanPairProofRequiresBaselineControlAndIdenticalSecondBranches(t *testing.T) {
	proof := &BooleanPairProof{
		BaselineHash: "base", FirstTrueHash: "base", FirstFalseHash: "false",
		ReplayTrueHash: "base", ReplayFalseHash: "false",
		SecondTrueHash: "base", SecondFalseHash: "false",
		SyntaxControlHash: "base", Orientation: 1, SameSurface: true, SyntaxControlOK: true,
	}
	if !validBooleanPairProof(proof) {
		t.Fatal("complete boolean proof should be valid")
	}
	changedSecondPair := *proof
	changedSecondPair.SecondFalseHash = "different-router-page"
	if validBooleanPairProof(&changedSecondPair) {
		t.Fatal("same-orientation but value-specific second branch must not prove SQL execution")
	}
	mismatchedControl := *proof
	mismatchedControl.SyntaxControlHash = "parser-specific-page"
	if validBooleanPairProof(&mismatchedControl) {
		t.Fatal("syntax control must match the normalized native baseline")
	}
}

func TestMismatchedOASTCorrelationIsRejected(t *testing.T) {
	r := NewEngine(nil, nil).Verify(Candidate{
		ScanID: "scan-a", Module: "ssrf", VulnClass: "ssrf", EndpointURL: "https://target.test/fetch",
		Baseline: ResponseSnapshot{Body: "same"}, Probe: ResponseSnapshot{Body: "same"},
		OAST: &oast.Correlation{ScanID: "scan-b", PayloadID: "p1", EndpointURL: "https://other.test/fetch",
			VulnClass: "ssrf", CallbackURL: "https://p1.oast.test/"},
	})
	if r.OASTConfirmed || !hasReason(r, ReasonOASTMismatch) {
		t.Fatalf("cross-scan/cross-endpoint OAST correlation must be rejected: %+v", r)
	}
}

func TestDOMXSSExecutionConfirmation(t *testing.T) {
	html := `<html data-akca-xss="executed"><script>document.documentElement.setAttribute('data-akca-xss','executed')</script></html>`
	if !CheckDOMExecution(html) {
		t.Fatal("expected dom execution detection")
	}
	level, reason := SeparateDOMExecution(true, false)
	if level != Potential || reason != ReasonDOMPresenceOnly {
		t.Fatalf("got level=%s reason=%s", level, reason)
	}
	if DOMXSSPayload() == "" {
		t.Fatal("expected dom xss payload")
	}
}

func TestErrorFingerprintLibrary(t *testing.T) {
	cases := []struct {
		body string
		src  string
	}{
		{"Attention Required! Ray ID abc", "Cloudflare"},
		{"Request blocked by AWS WAF", "AWS WAF"},
		{"Access Denied Reference #", "Akamai"},
		{"ModSecurity action", "ModSecurity"},
		{"Incapsula incident", "Imperva"},
	}
	for _, tc := range cases {
		fp, ok := MatchErrorFingerprint(tc.body, 403, nil)
		if !ok || fp.Source != tc.src {
			t.Fatalf("body=%q expected %s got %+v", tc.body, tc.src, fp)
		}
	}
}

func TestHoneypotDetection(t *testing.T) {
	canaries := []string{"canary-a", "canary-b", "canary-c"}
	bodies := []string{
		"echo canary-a debug",
		"echo canary-b debug",
		"echo canary-c debug",
	}
	if !DetectHoneypot(canaries, bodies) {
		t.Fatal("expected honeypot detection")
	}
	r := NewEngine(nil, nil).Verify(Candidate{
		ScanID: "s1", HoneypotCanaries: canaries, HoneypotBodies: bodies,
		Baseline: ResponseSnapshot{Body: "ok"}, Probe: ResponseSnapshot{Body: bodies[0]},
	})
	if !r.Suppressed {
		t.Fatal("honeypot should suppress finding")
	}
}

func TestOASTCorrelationUpgrade(t *testing.T) {
	r := NewEngine(nil, nil).Verify(Candidate{
		ScanID: "s1", EndpointURL: "http://x.test/fetch",
		Baseline: ResponseSnapshot{Body: "ok"},
		Probe:    ResponseSnapshot{Body: "blind"},
		OAST: &oast.Correlation{
			ScanID: "s1", PayloadID: "pl-blind", EndpointURL: "http://x.test/fetch",
			CallbackURL: "https://pl-blind.oast.test/",
		},
		StabilityRuns:   repeatProbe("blind", 5),
		PolymorphicHits: []bool{true, true},
	})
	if !r.OASTConfirmed {
		t.Fatal("expected oast confirmed")
	}
	if r.Confidence != Confirmed && r.Confidence != HighConfidence {
		t.Fatalf("expected upgraded confidence, got %s", r.Confidence)
	}
}

func TestOASTIsNotSuppressedWhenResponseMatchesBaseline(t *testing.T) {
	r := NewEngine(nil, nil).Verify(Candidate{
		ScanID: "s1", Module: "ssrf", VulnClass: "ssrf", EndpointURL: "http://x.test/fetch",
		Baseline: ResponseSnapshot{StatusCode: 200, Body: "same"},
		Probe:    ResponseSnapshot{StatusCode: 200, Body: "same"},
		OAST: &oast.Correlation{
			ScanID: "s1", PayloadID: "callback-1", EndpointURL: "http://x.test/fetch",
			VulnClass: "ssrf", CallbackURL: "https://callback-1.oast.test/",
		},
	})
	if r.Suppressed || !r.OASTConfirmed {
		t.Fatalf("correlated OAST evidence must survive baseline suppression: %+v", r)
	}
}

func TestStabilityRejectsUnrelatedChangingResponses(t *testing.T) {
	base := ResponseSnapshot{StatusCode: 200, Body: "normal response"}
	runs := []ResponseSnapshot{
		{StatusCode: 200, Body: "first unrelated page"},
		{StatusCode: 200, Body: "second random result"},
		{StatusCode: 200, Body: "third changing output"},
	}
	matches := StabilityFromRuns(base, runs)
	_, _, suppress := EvaluateStability(matches)
	if !suppress {
		t.Fatalf("changing responses must not count as stable: %v", matches)
	}
}

func TestStabilityAllowsVolatileTimestamps(t *testing.T) {
	base := ResponseSnapshot{StatusCode: 200, Body: "normal response"}
	runs := []ResponseSnapshot{
		{StatusCode: 500, Body: "sql error at 2026-07-13T10:00:00Z"},
		{StatusCode: 500, Body: "sql error at 2026-07-13T10:00:01Z"},
		{StatusCode: 500, Body: "sql error at 2026-07-13T10:00:02Z"},
	}
	_, level, suppress := EvaluateStability(StabilityFromRuns(base, runs))
	if suppress || level != HighConfidence {
		t.Fatalf("timestamp-only changes should remain stable, level=%s suppress=%v", level, suppress)
	}
}

func TestGenericNotAcceptableDoesNotImpersonateModSecurity(t *testing.T) {
	if fp, ok := MatchErrorFingerprint("406 Not Acceptable", 406, nil); ok && fp.Source == "ModSecurity" {
		t.Fatalf("generic response was misclassified as ModSecurity: %+v", fp)
	}
}

func TestFrameworkErrorDowngradesWithoutHardSuppression(t *testing.T) {
	r := NewEngine(nil, nil).Verify(Candidate{
		ScanID: "s1", Module: "sqli", VulnClass: "sqli",
		Baseline:      ResponseSnapshot{StatusCode: 200, Body: "ok"},
		Probe:         ResponseSnapshot{StatusCode: 500, Body: "Whoops laravel SQLSTATE syntax error"},
		StabilityRuns: repeatProbe("Whoops laravel SQLSTATE syntax error", 3),
	})
	if r.Suppressed {
		t.Fatalf("framework exception with differential evidence should be downgraded, not suppressed: %+v", r)
	}
}

func TestPersistence(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/verify.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_ = db.Migrate()
	engine := NewEngine(db, func(string, string, map[string]interface{}) error { return nil })
	_ = engine.Verify(Candidate{ScanID: "scan-v", Title: "test", Baseline: ResponseSnapshot{Body: "a"}, Probe: ResponseSnapshot{Body: "b"}})
}

func repeatProbe(body string, n int) []ResponseSnapshot {
	out := make([]ResponseSnapshot, n)
	for i := range out {
		out[i] = ResponseSnapshot{StatusCode: 200, Body: body, ContentType: "text/html"}
	}
	return out
}

func hasReason(result Result, expected DowngradeReason) bool {
	for _, reason := range result.DowngradeReasons {
		if reason == expected {
			return true
		}
	}
	return false
}

func TestLearningFalsePositiveDowngrade(t *testing.T) {
	base := ResponseSnapshot{StatusCode: 200, Body: "baseline"}
	probe := ResponseSnapshot{StatusCode: 200, Body: "probe differs unique"}
	r := NewEngine(nil, nil).Verify(Candidate{
		ScanID: "s", Title: "xss", VulnClass: "xss", EndpointURL: "http://x", Method: "GET",
		Parameter: "q", Payload: "p", Module: "xss",
		Baseline: base, Probe: probe, LearningFP: 0.6,
		PolymorphicHits: []bool{true, true},
		StabilityRuns:   repeatProbe(probe.Body, 5),
	})
	if r.Score >= 0.9 {
		t.Fatalf("expected learning FP downgrade, score=%f conf=%s", r.Score, r.Confidence)
	}
}

func TestConfidenceScoreIsClampedToOne(t *testing.T) {
	level, score := ScoreConfidence(Candidate{
		NegativeControlSet: true,
		DOMExecuted:        true,
	}, Result{
		SemanticDiff:      true,
		PolymorphicOK:     true,
		StabilityRatio:    1,
		OASTConfirmed:     true,
		TimingConfirmed:   true,
		TypedReplayRatio:  1,
		NegativeControlOK: true,
	})
	if level != Confirmed || score != 1 {
		t.Fatalf("confidence must be normalized: level=%s score=%f", level, score)
	}
}

func TestTypedContentSignalAloneCannotBecomeConfirmed(t *testing.T) {
	level, score := ScoreConfidence(Candidate{DirectTypedSignal: true}, Result{
		SemanticDiff: true,
		ProofType:    ProofContentEvidence,
	})
	if level != Potential || score >= 0.75 {
		t.Fatalf("single typed signal must remain a potential lead: level=%s score=%f", level, score)
	}
}
