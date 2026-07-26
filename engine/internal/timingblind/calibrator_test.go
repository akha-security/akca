package timingblind

import "testing"

func TestRecommendSleepSecHighLatency(t *testing.T) {
	b := Calibrate([]int64{2800, 2600, 3000, 2700, 2900})
	if got := RecommendSleepSec(b); got < 7 {
		t.Fatalf("expected longer sleep for high latency, got %d", got)
	}
}

func TestVerifyProbeMatch(t *testing.T) {
	b := Calibrate([]int64{120, 130, 110, 125, 115})
	sleep := 5
	probeMs := int64(b.AvgMs + float64(sleep*1000))
	ok, _ := VerifyProbe(probeMs, b, sleep)
	if !ok {
		t.Fatalf("expected timing match at %dms baseline avg %.0f", probeMs, b.AvgMs)
	}
}

func TestVerifyProbeNoiseRejected(t *testing.T) {
	b := Calibrate([]int64{120, 400, 90, 350, 110})
	ok, _ := VerifyProbe(180, b, 5)
	if ok {
		t.Fatal("high jitter baseline should reject short probe")
	}
}

func TestRewriteSleepDuration(t *testing.T) {
	got := RewriteSleepDuration(`' AND SLEEP(5)-- -`, 7)
	if got != `' AND SLEEP(7)-- -` {
		t.Fatalf("unexpected rewrite: %q", got)
	}
}

func TestRewriteRequestedXORSleepDuration(t *testing.T) {
	payload := `0'XOR(if(now()=sysdate(),sleep(6),0))XOR'Z`
	got := RewriteSleepDuration(payload, 8)
	if got != `0'XOR(if(now()=sysdate(),sleep(8),0))XOR'Z` {
		t.Fatalf("unexpected XOR rewrite: %q", got)
	}
}

func TestMatchedZeroDelayPreservesXORShape(t *testing.T) {
	payload := `0'XOR(if(now()=sysdate(),sleep(6),0))XOR'Z`
	control := SQLiMatchedZeroDelayPayload(payload, "mysql")
	if control.Value != `0'XOR(if(now()=sysdate(),SLEEP(0),0))XOR'Z` ||
		!control.IsControl || !control.IsNegativeControl {
		t.Fatalf("unexpected matched zero control: %+v", control)
	}
}

func TestXORFalseConditionKeepsSleep(t *testing.T) {
	payload := `0'XOR(if(now()=sysdate(),sleep(6),0))XOR'Z`
	control, ok := SQLiXORFalseConditionControl(payload)
	if !ok || control.Value != `0'XOR(if(now()!=now(),sleep(6),0))XOR'Z` {
		t.Fatalf("unexpected XOR false-condition control: %+v", control)
	}
}

func TestVerifyProbeWithControl(t *testing.T) {
	b := Calibrate([]int64{120, 130, 110, 125, 115})
	sleep := 5
	delay := int64(b.AvgMs + float64(sleep*1000))
	zero := int64(b.AvgMs + 20)
	ok, _ := VerifyProbeWithControl(delay, zero, b, sleep)
	if !ok {
		t.Fatal("expected timing with zero control to match")
	}
}
