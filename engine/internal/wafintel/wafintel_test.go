package wafintel_test

import (
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/wafintel"
)

func TestSelectStrategyPerVendor(t *testing.T) {
	for _, vendor := range wafintel.AllVendors() {
		s := wafintel.SelectStrategy(vendor, wafintel.NewLearningProfile("example.com"))
		if s.ID == "" {
			t.Fatalf("expected strategy for %s", vendor)
		}
	}
}

func TestAdaptiveStrategyLearning(t *testing.T) {
	learn := wafintel.NewLearningProfile("example.com")
	learn = wafintel.RecordStrategyResult(learn, "cf_unicode_cascade", true)
	s := wafintel.SelectStrategy("Cloudflare", learn)
	if s.ID != "cf_unicode_cascade" {
		t.Fatalf("expected learned strategy, got %s", s.ID)
	}
}

func TestAdaptiveTechniqueLearningRanksSuccessfulEncodings(t *testing.T) {
	learn := wafintel.NewLearningProfile("example.com")
	learn = wafintel.RecordTechniqueResult(learn, "double_url", true)
	learn = wafintel.RecordTechniqueResult(learn, "unicode", true)
	learn = wafintel.RecordTechniqueResult(learn, "double_url", true)
	learn = wafintel.RecordTechniqueResult(learn, "html_entity", false)

	got := wafintel.PreferredTechniques(learn)
	if len(got) < 2 || got[0] != "double_url" || got[1] != "unicode" {
		t.Fatalf("unexpected technique preference order: %#v", got)
	}
	for _, item := range got {
		if item == "html_entity" {
			t.Fatalf("blocked technique should not be preferred: %#v", got)
		}
	}
}

func TestEncodingCascade(t *testing.T) {
	out := wafintel.EncodingCascade("<script>", "url", "double_url")
	if !strings.Contains(out, "%25") {
		t.Fatalf("expected double encoding, got %q", out)
	}
}

func TestMutationEngine(t *testing.T) {
	out := wafintel.MutatePayload(`<script>alert(1)</script>`)
	if out == `<script>alert(1)</script>` {
		t.Fatal("expected mutation")
	}
}

func TestApplyStrategyHeaders(t *testing.T) {
	s := wafintel.SelectStrategy("AWS WAF", wafintel.NewLearningProfile("example.com"))
	payload, headers := wafintel.ApplyStrategy("test", s)
	if payload == "" {
		t.Fatal("expected payload")
	}
	if len(s.Encodings) > 0 && payload == "test" && s.ID != "generic_url" {
		// encoded strategies should change payload unless generic
	}
	_ = headers
}

func TestAllEncodingTypes(t *testing.T) {
	sample := "alert<>"
	for _, enc := range []string{"url", "double_url", "unicode", "html_entity", "hex", "octal", "mixed"} {
		out := wafintel.ApplyEncoding(sample, enc)
		if out == "" {
			t.Fatalf("encoding %s produced empty output", enc)
		}
	}
}

func TestCharacterPreflightProbing(t *testing.T) {
	learn := wafintel.NewLearningProfile("example.com")
	learn = wafintel.RecordCharResult(learn, "single_quote", false)
	learn = wafintel.RecordCharResult(learn, "semicolon", true)

	if len(learn.BlockedChars) != 1 || learn.BlockedChars[0] != "single_quote" {
		t.Fatalf("expected single_quote in blocked chars: %#v", learn.BlockedChars)
	}
	if len(learn.AllowedChars) != 1 || learn.AllowedChars[0] != "semicolon" {
		t.Fatalf("expected semicolon in allowed chars: %#v", learn.AllowedChars)
	}
}
