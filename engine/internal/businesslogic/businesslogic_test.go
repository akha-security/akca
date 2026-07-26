package businesslogic

import "testing"

func TestAnalyzeNegativeQuantity(t *testing.T) {
	ok, sig := Analyze("total: 100", "order confirmed total: -50", Probe{Name: "qty_negative_one", Value: "-1", Signal: "negative_quantity_accepted"})
	if !ok || sig != "negative_total_anomaly" {
		t.Fatalf("got ok=%v sig=%q", ok, sig)
	}
}

func TestAnalyzePriceManipulation(t *testing.T) {
	ok, sig := Analyze("total: 100", "order confirmed total: 1", Probe{Name: "price_zero", Value: "1", Signal: "zero_price_accepted"})
	if !ok {
		t.Fatal("expected price manipulation signal")
	}
	if sig == "" {
		t.Fatal("expected non-empty signal")
	}
}

func TestAllProbesQuantityParam(t *testing.T) {
	probes := AllProbes("quantity")
	if len(probes) < 10 {
		t.Fatalf("expected many probes, got %d", len(probes))
	}
	if probes[0].Signal != "negative_quantity_accepted" {
		t.Fatalf("quantity param should prioritize qty probes, got %q", probes[0].Signal)
	}
}

func TestFinancialProbesIncludeNaN(t *testing.T) {
	found := false
	for _, p := range FinancialProbes() {
		if p.Value == "NaN" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected NaN probe")
	}
}
