package payloadgen

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/reflection"
	"github.com/akha-security/akca/engine/internal/storage"
)

func TestWAFControlsRemainLinkedAfterNormalizationAndSelection(t *testing.T) {
	for _, budget := range []int{4, 15, 50, -1} {
		result := Generate(Input{Profile: reflection.ReflectionProfile{ScanID: "scan", EndpointURL: "https://target.test", Parameter: "q", ParameterLocation: "query", Context: reflection.ContextHTML}, WAF: WAFHints{Vendor: "Cloudflare", AllowEvasion: true}, Tech: TechHints{Database: "mysql"}, Budget: budget})
		controls := map[string]int{}
		offensive := map[string]bool{}
		for _, p := range result.Payloads {
			if p.ControlFor != "" {
				controls[p.ControlFor]++
			}
			if !p.IsControl && !p.IsNegativeControl {
				offensive[p.SemanticKey] = true
			}
		}
		for _, p := range result.Payloads {
			if p.WAFAdapted && !p.IsNegativeControl && controls[p.SemanticKey] != 1 {
				t.Fatalf("budget=%d missing control for %s", budget, p.SemanticKey)
			}
		}
		for key := range controls {
			if !offensive[key] {
				t.Fatalf("orphan control for %s", key)
			}
		}
	}
}

func TestGroupBWAFControlIdentitySurvivesNormalization(t *testing.T) {
	for _, family := range []string{"ssrf", "lfi", "xxe"} {
		payloads := GenerateGroupB(family, "", WAFHints{Vendor: "Cloudflare", AllowEvasion: true})
		keys := map[string]bool{}
		for _, p := range payloads {
			keys[p.SemanticKey] = true
		}
		for _, p := range payloads {
			if p.ControlFor != "" && !keys[p.ControlFor] {
				t.Fatalf("%s orphan control for %s", family, p.ControlFor)
			}
		}
	}
}

func TestDedupeKeepsExactValuesAndControlRelationships(t *testing.T) {
	var values []Payload
	for _, value := range []string{"TokenA", "tokena", " TokenA", "TokenA "} {
		p := normalizePayload(Payload{Value: value, VulnClass: "xss", Family: "xss"}, reflection.ReflectionProfile{})
		values = append(values, p)
	}
	if got := len(semanticDedupe(values)); got != 4 {
		t.Fatalf("case/space collapsed: %d", got)
	}
	controls := []Payload{normalizePayload(Payload{Value: "same", IsNegativeControl: true, ControlFor: "one"}, reflection.ReflectionProfile{}), normalizePayload(Payload{Value: "same", IsNegativeControl: true, ControlFor: "two"}, reflection.ReflectionProfile{})}
	if got := len(semanticDedupe(controls)); got != 2 {
		t.Fatalf("control relationships collapsed: %d", got)
	}
}

func TestTransportEncodingMatchesMultipartAndFormBuilders(t *testing.T) {
	for _, location := range []string{"multipart", "form", "body", "post"} {
		value, _ := adjustWAFForTransport("a/b", "a%252Fb", "double_url", location)
		want := "a%2Fb"
		if location == "multipart" {
			want = "a%252Fb"
		}
		if value != want {
			t.Fatalf("%s=%q want %q", location, value, want)
		}
	}
}

func TestSQLCommentCaseKeepsOpaqueData(t *testing.T) {
	input := "SELECT 'MiXeD Value', \"CaseSensitive\", `MiXeD`, [Select], $$SeLeCt Value$$, $tag$SELECT Value$tag$ FROM TableName -- Keep Comment\nWHERE id = 1 /* Keep Me */"
	got := applyWAFTechnique(input, "comment_case")
	for _, kept := range []string{"'MiXeD Value'", `"CaseSensitive"`, "`MiXeD`", "[Select]", "$$SeLeCt Value$$", "$tag$SELECT Value$tag$", "TableName", "-- Keep Comment\n", "/* Keep Me */"} {
		if !strings.Contains(got, kept) {
			t.Fatalf("changed %q in %q", kept, got)
		}
	}
	if !strings.Contains(got, "/**/") {
		t.Fatal("outside separator not transformed")
	}
}

func TestGeneratorHonorsExplicitBudgetAndScanIdentity(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/generator.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Migrate(); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultScanConfig()
	cfg.PayloadBudget = config.PayloadBudgetHigh
	g := NewGenerator("scan", db, cfg, func(string, string, map[string]interface{}) error { return nil })
	results, err := g.Run(context.Background(), []reflection.ReflectionProfile{{ScanID: "wrong", EndpointURL: "https://target.test", Method: "POST", Parameter: "name", ParameterLocation: "json", Context: reflection.ContextJSON}})
	if err != nil || len(results) != 1 {
		t.Fatalf("generation: %v %+v", err, results)
	}
	if results[0].BudgetLimit != cfg.PayloadBudgetLimit() || results[0].ScanID != "scan" {
		t.Fatalf("budget/identity changed: %+v", results[0])
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := g.Run(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("empty generation swallowed cancel: %v", err)
	}
}

func TestGenerationIdentityKeepsNativeMethodSeparateFromDeliveryMethod(t *testing.T) {
	result := Generate(Input{Profile: reflection.ReflectionProfile{Method: "POST", NativeMethod: "GET", ParameterLocation: "form"}, Budget: 1})
	if result.Method != "GET" {
		t.Fatalf("native method overwritten by delivery method: %q", result.Method)
	}
}
