package payloadgen

import (
	"context"
	"net/url"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/models"
	"github.com/akha-security/akca/engine/internal/reflection"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/wafintel"
)

func TestAutoWAFGenerationIsHostAndPortScoped(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/auto.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureScan("auto"); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveWAFProfile("auto", models.WAFProfile{Host: "waf.test:8443", Vendor: "Cloudflare"}); err != nil {
		t.Fatal(err)
	}
	// An old host learning record must not activate adaptation on an unprofiled host.
	if err := db.SaveWAFLearningProfile("plain.test", wafintel.LearningProfile{Domain: "plain.test", TechniqueScores: map[string]int{"double_url": 10}}); err != nil {
		t.Fatal(err)
	}
	var profiles []reflection.ReflectionProfile
	for _, endpoint := range []string{"https://waf.test:8443/search", "https://plain.test/search", "https://waf.test:9443/search"} {
		profiles = append(profiles, reflection.ReflectionProfile{EndpointURL: endpoint, Method: "GET", Parameter: "q", ParameterLocation: "query", Context: reflection.ContextHTML, ReflectionKind: reflection.ReflectionRaw})
	}
	cfg := config.DefaultScanConfig()
	g := NewGenerator("auto", db, cfg, func(string, string, map[string]interface{}) error { return nil })
	results, err := g.Run(context.Background(), profiles)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(profiles) {
		t.Fatalf("results=%d", len(results))
	}
	for i, result := range results {
		adapted := 0
		for _, p := range result.Payloads {
			if p.WAFAdapted && !p.IsNegativeControl {
				adapted++
			}
		}
		if (adapted > 0) != (i == 0) {
			t.Fatalf("host scoping failed for %s: adapted=%d", result.EndpointURL, adapted)
		}
		if i == 0 {
			assertBoundedWAFPairs(t, result.Payloads, 2)
		}
	}
	if cfg.EnableWAFBypassHeaders {
		t.Fatal("auto enabled bypass headers")
	}
}

func assertBoundedWAFPairs(t *testing.T, payloads []Payload, limit int) {
	t.Helper()
	raw := map[string]bool{}
	controls := map[string]bool{}
	counts := map[string]int{}
	for _, p := range payloads {
		if !p.WAFAdapted && !p.IsControl && !p.IsNegativeControl {
			raw[baseVariantKey(p)] = true
		}
		if p.WAFAdapted && p.IsNegativeControl {
			controls[p.ControlFor] = true
		}
	}
	for _, p := range payloads {
		if !p.WAFAdapted || p.IsNegativeControl {
			continue
		}
		key := baseVariantKey(p)
		if !raw[key] || !controls[p.SemanticKey] {
			t.Fatalf("adapted variant missing raw or matched control: %+v", p)
		}
		counts[key]++
		if counts[key] > limit {
			t.Fatalf("variant cap exceeded for %s: %d", key, counts[key])
		}
	}
}

func TestWAFAutoModesSignalsAndTechniqueOrdering(t *testing.T) {
	cfg := config.DefaultScanConfig()
	learn := wafintel.NewLearningProfile("waf.test")
	learn.TechniqueScores = map[string]int{"double_url": 5, "unicode_url": -3}
	for _, p := range []models.WAFProfile{{}, {CDN: "Cloudflare", CautiousModeRecommended: true}} {
		if WAFHintsForProfile(cfg, p, learn).AllowEvasion {
			t.Fatal("learning/CDN alone enabled auto")
		}
	}
	if !WAFHintsForProfile(cfg, models.WAFProfile{ChallengePageDetected: true}, learn).AllowEvasion {
		t.Fatal("observed challenge did not enable generic variants")
	}
	hints := WAFHintsForProfile(cfg, models.WAFProfile{Vendor: "Cloudflare"}, learn)
	profile := reflection.ReflectionProfile{Context: reflection.ContextUnknown, ParameterLocation: "query"}
	base := normalizePayload(Payload{Value: "' UNION SELECT 1--", VulnClass: "sqli", Family: "sqli", Variant: "fixture", ExpectedSignal: "sql_error", Priority: 80}, profile)
	variants := wafEvasionVariants(Input{Profile: profile, WAF: hints}, []Payload{base})
	if len(variants) == 0 || variants[0].Encoding != "double_url" {
		t.Fatalf("learned technique not first: %+v", variants)
	}
	for _, p := range variants {
		if p.Encoding == "unicode_url" {
			t.Fatal("failed technique was not avoided")
		}
	}
	assertBoundedWAFPairs(t, append([]Payload{base}, variants...), 2)
	cfg.WAFPayloadMode = config.WAFPayloadOff
	if WAFHintsForProfile(cfg, models.WAFProfile{Vendor: "Cloudflare"}, learn).AllowEvasion {
		t.Fatal("off still allows variants")
	}
	cfg.WAFPayloadMode = config.WAFPayloadOn
	forced := WAFHintsForProfile(cfg, models.WAFProfile{}, learn)
	if len(wafEvasionVariants(Input{Profile: profile, WAF: forced}, []Payload{base})) == 0 {
		t.Fatal("forced generic adaptation produced no variants")
	}
	cfg.PassiveMode = true
	if WAFHintsForProfile(cfg, models.WAFProfile{Vendor: "Cloudflare"}, learn).AllowEvasion {
		t.Fatal("passive mode enabled forced variants")
	}
}

func TestRuntimeGroupBAccountsForQueryTransport(t *testing.T) {
	hints := WAFHintsForProfile(config.DefaultScanConfig(), models.WAFProfile{Vendor: "Cloudflare"}, wafintel.NewLearningProfile("waf.test"))
	payloads := GenerateGroupBForProfile("ssrf", "", hints, reflection.ReflectionProfile{ParameterLocation: "query"})
	raw := map[string]string{}
	for _, p := range payloads {
		if !p.WAFAdapted {
			raw[baseVariantKey(p)] = p.Value
		}
	}
	checked := 0
	for _, p := range payloads {
		if !p.WAFAdapted || p.IsNegativeControl {
			continue
		}
		if p.Encoding == "url" {
			t.Fatal("query builder already supplies the single URL layer")
		}
		if p.Encoding == "double_url" {
			if want := url.QueryEscape(raw[baseVariantKey(p)]); p.Value != want {
				t.Fatalf("incorrect pre-transport depth: got %q want %q", p.Value, want)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no double URL variants checked")
	}
}

func TestStoredWAFPayloadOptOutRemovesControlsAndPlans(t *testing.T) {
	profile := reflection.ReflectionProfile{EndpointURL: "https://waf.test", ParameterLocation: "query", Context: reflection.ContextHTML, ReflectionKind: reflection.ReflectionRaw}
	hints := WAFHintsForProfile(config.DefaultScanConfig(), models.WAFProfile{Vendor: "Cloudflare"}, wafintel.NewLearningProfile("waf.test"))
	generated := Generate(Input{Profile: profile, WAF: hints, Budget: -1})
	hadAdapted := false
	for _, p := range generated.Payloads {
		hadAdapted = hadAdapted || p.WAFAdapted
	}
	if !hadAdapted {
		t.Fatal("fixture has no adapted payloads")
	}
	filtered := WithoutWAFAdaptation(generated)
	for _, p := range filtered.Payloads {
		if p.WAFAdapted {
			t.Fatal("persisted adapted payload survived opt-out")
		}
	}
	for _, tc := range filtered.TestCases {
		for _, p := range tc.Payloads {
			if p.WAFAdapted {
				t.Fatal("adapted payload survived in a test plan")
			}
		}
	}
	if len(filtered.Payloads) == 0 {
		t.Fatal("opt-out removed original payloads")
	}
}
