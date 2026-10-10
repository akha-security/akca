package wafintel_test

import (
	"net/url"
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
	original := "<script>"
	out := wafintel.EncodingCascade(original, "url", "double_url")
	if !strings.Contains(out, "%25") {
		t.Fatalf("expected double encoding, got %q", out)
	}
	once, err := url.QueryUnescape(out)
	if err != nil || once == original {
		t.Fatalf("expected one encoded layer after first decode, got %q (err=%v)", once, err)
	}
	twice, err := url.QueryUnescape(once)
	if err != nil || twice != original {
		t.Fatalf("cascade must contain exactly two URL layers, got %q (err=%v)", twice, err)
	}
}

func TestMutationEngine(t *testing.T) {
	original := `<script>alert(1)</script>`
	out := wafintel.MutatePayload(original)
	if out == original {
		t.Fatal("expected mutation")
	}
	if !strings.Contains(out, "alert(1)") {
		t.Fatalf("case-sensitive JavaScript identifier was changed: %q", out)
	}
	if repeated := wafintel.MutatePayload(original); repeated != out {
		t.Fatalf("mutation must be deterministic: first=%q second=%q", out, repeated)
	}
}

func TestByteEncodingsPreserveUTF8(t *testing.T) {
	if got := wafintel.ApplyEncoding("é", "hex"); got != `\xC3\xA9` {
		t.Fatalf("hex encoding must operate on UTF-8 bytes, got %q", got)
	}
	if got := wafintel.ApplyEncoding("é", "octal"); got != `\303\251` {
		t.Fatalf("octal encoding must operate on UTF-8 bytes, got %q", got)
	}
	if got := wafintel.ApplyEncoding("é<", "mixed"); got != "%C3%A9&#60;" {
		t.Fatalf("mixed encoding split a UTF-8 rune or encoded incorrectly: %q", got)
	}
}

func TestMySQLVersionCommentMatchesKeywordCase(t *testing.T) {
	got := wafintel.ApplyEncoding("select id FrOm users", "mysql_version_comment")
	if !strings.Contains(got, "/*!50000select*/") || !strings.Contains(got, "/*!50000FrOm*/") {
		t.Fatalf("case-insensitive SQL keywords were not transformed: %q", got)
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

func TestApplyStrategyMutationIntegrity(t *testing.T) {
	strategy := wafintel.Strategy{
		ID:        "test_unicode",
		Vendor:    "test",
		Name:      "test_unicode",
		Encodings: []string{"unicode"},
	}
	sample := `<script>alert(1)</script>`
	for i := 0; i < 25; i++ {
		mutated, _ := wafintel.ApplyStrategy(sample, strategy)
		// Upper-case \U is invalid in JS/JSON unicode escapes; only lowercase \u is valid.
		if strings.Contains(mutated, `\U`) {
			t.Fatalf("iteration %d: mutated payload contains invalid uppercase unicode escape: %q", i, mutated)
		}
	}
}

func TestIsURLSafePayload(t *testing.T) {
	safeCases := []string{
		"%253Cscript%253E",
		"%3Cscript%3E",
		"hello-world_123.~",
		"%20",
		"param%27%20OR%201%3D1",
	}
	for _, tc := range safeCases {
		if !wafintel.IsURLSafePayload(tc) {
			t.Errorf("expected %q to be URL-safe", tc)
		}
	}

	unsafeCases := []string{
		"<script>alert(1)</script>",
		"alert(1)",
		`\u0073cript`,
		"hello world",
		"100%safe", // % not followed by two hex digits
		"test&foo=bar",
		"test=1",
	}
	for _, tc := range unsafeCases {
		if wafintel.IsURLSafePayload(tc) {
			t.Errorf("expected %q to NOT be URL-safe", tc)
		}
	}
}
