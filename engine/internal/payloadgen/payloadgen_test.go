package payloadgen

import (
	"reflect"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/reflection"
)

func TestPayloadRankingAndBudget(t *testing.T) {
	profile := reflection.ReflectionProfile{
		EndpointURL: "http://example.com/search", Parameter: "q",
		CanaryValue: "akca11119z", ReflectionKind: reflection.ReflectionRaw,
		Context: reflection.ContextHTML, QuoteType: "none", Stable: true,
	}
	result := Generate(Input{
		Profile: profile,
		Tech:    TechHints{BackendLanguage: "php", Database: "mysql"},
		Budget:  5,
	})
	if len(result.Payloads) == 0 {
		t.Fatal("expected payloads")
	}
	if result.BudgetUsed > result.BudgetLimit {
		t.Fatalf("budget exceeded: used=%d limit=%d", result.BudgetUsed, result.BudgetLimit)
	}
	if result.Payloads[0].Priority < result.Payloads[len(result.Payloads)-1].Priority {
		t.Fatal("payloads should be ranked by descending priority")
	}
}

// TestUnknownTechStillGeneratesInjectionPayloads guards the regression where
// SQLi/SSTI/command-injection payloads were only generated when fingerprinting
// positively identified the backend stack. On most real targets (CDN/WAF in
// front, minimal headers) the stack is unknown, which silently disabled those
// classes entirely — the scanner only ever reported passive/secret findings.
func TestUnknownTechStillGeneratesInjectionPayloads(t *testing.T) {
	result := Generate(Input{
		Profile: reflection.ReflectionProfile{
			CanaryValue: "akca11119z", ReflectionKind: reflection.ReflectionRaw,
			Context: reflection.ContextHTML,
		},
		Tech:   TechHints{}, // unknown stack
		Budget: 200,
	})
	families := map[string]bool{}
	for _, p := range result.Payloads {
		families[p.Family] = true
	}
	for _, want := range []string{"xss", "sqli", "ssti", "command_injection"} {
		if !families[want] {
			t.Fatalf("unknown tech should still generate %s payloads; got families %v", want, families)
		}
	}
}

func TestGoFingerprintDoesNotDisableSQLiPayloads(t *testing.T) {
	result := Generate(Input{
		Profile: reflection.ReflectionProfile{
			CanaryValue: "akca11119z", ReflectionKind: reflection.ReflectionRaw,
			Context: reflection.ContextUnknown, Parameter: "id",
		},
		Tech:   TechHints{BackendLanguage: "Go", Framework: "net/http"},
		Budget: 50,
	})
	for _, payload := range result.Payloads {
		if payload.Family == "sqli" {
			return
		}
	}
	t.Fatalf("a Go fingerprint must rank, not disable, SQLi coverage: %+v", result.Skipped)
}

func TestSemanticDeduplication(t *testing.T) {
	payloads := []Payload{
		{VulnClass: "xss", Family: "xss", ExpectedSignal: "dom_mutation", Variant: "a"},
		{VulnClass: "xss", Family: "xss", ExpectedSignal: "dom_mutation", Variant: "b"},
	}
	for i := range payloads {
		payloads[i].SemanticKey = semanticKey(payloads[i])
	}
	out := semanticDedupe(payloads)
	if len(out) != 1 {
		t.Fatalf("expected semantic dedupe to 1, got %d", len(out))
	}
}

func TestExpectedSignalMetadata(t *testing.T) {
	profile := reflection.ReflectionProfile{
		CanaryValue: "akca11119z", ReflectionKind: reflection.ReflectionRaw,
		Context: reflection.ContextJavaScript,
	}
	result := Generate(Input{Profile: profile, Tech: TechHints{Framework: "django"}})
	foundXSS := false
	for _, p := range result.Payloads {
		if p.VulnClass == "xss" && p.ExpectedSignal == "" {
			t.Fatal("payload missing expected signal")
		}
		if p.VulnClass == "xss" {
			foundXSS = true
		}
		if p.VerificationStrategy == "" || p.SelectionReason == "" {
			t.Fatal("payload missing verification metadata")
		}
	}
	if !foundXSS {
		t.Fatal("expected xss payloads for js context")
	}
}

func TestPerTargetLearningSkipsBlockedFamilies(t *testing.T) {
	profile := reflection.ReflectionProfile{
		CanaryValue: "akca11119z", ReflectionKind: reflection.ReflectionRaw,
		Context: reflection.ContextHTML,
	}
	result := Generate(Input{
		Profile: profile,
		Tech:    TechHints{BackendLanguage: "php", Database: "mysql"},
		Budget:  50,
		Learn:   LearningProfile{Blocked: []string{"sqli"}},
	})
	for _, p := range result.Payloads {
		if p.Family == "sqli" {
			t.Fatal("blocked sqli family should be skipped")
		}
	}
}

func TestSkipReasonsRecorded(t *testing.T) {
	profile := reflection.ReflectionProfile{
		CanaryValue: "akca11119z", ReflectionKind: reflection.ReflectionPartial,
		Context: reflection.ContextHTML, BlockedChars: []string{"<"},
	}
	result := Generate(Input{Profile: profile, Tech: TechHints{}, Budget: 15})
	if len(result.Skipped) == 0 {
		t.Fatal("expected skipped family reasons")
	}
	found := false
	for _, s := range result.Skipped {
		if s.Family != "" && s.Reason != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("skip reasons should include family and reason")
	}
}

func TestLearningUpdate(t *testing.T) {
	learn := LearningProfile{}
	learn = UpdateLearning(learn, "xss", "blocked")
	if len(learn.Blocked) != 1 || learn.Blocked[0] != "xss" {
		t.Fatal("learning update failed")
	}
}

func TestDatabaseAwareSQLiPayloads(t *testing.T) {
	cases := map[string]string{
		"mysql":      "sleep(",
		"postgresql": "pg_sleep",
		"mssql":      "waitfor delay",
		"oracle":     "dbms_lock.sleep",
	}
	for db, marker := range cases {
		result := Generate(Input{
			Profile: reflection.ReflectionProfile{
				CanaryValue: "akca11119z", ReflectionKind: reflection.ReflectionRaw,
				Context: reflection.ContextHTML,
			},
			Tech:   TechHints{Database: db},
			Budget: 80,
		})
		found := false
		for _, p := range result.Payloads {
			if p.Family == "sqli" && strings.Contains(strings.ToLower(p.Value), marker) {
				found = true
			}
		}
		if !found {
			t.Errorf("expected %s-specific SQLi payload containing %q", db, marker)
		}
	}
}

func TestFrameworkAwareSSTIPayloads(t *testing.T) {
	result := Generate(Input{
		Profile: reflection.ReflectionProfile{
			CanaryValue: "akca11119z", ReflectionKind: reflection.ReflectionRaw,
			Context: reflection.ContextHTML,
		},
		Tech:   TechHints{Framework: "Freemarker"},
		Budget: 80,
	})
	found := false
	for _, p := range result.Payloads {
		if p.Family == "ssti" && strings.Contains(p.Value, "${17*19}") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected Freemarker-specific SSTI payload, got %+v", result.Payloads)
	}
}

func TestWindowsAwareCommandPayloads(t *testing.T) {
	result := Generate(Input{
		Profile: reflection.ReflectionProfile{
			CanaryValue: "akca11119z", ReflectionKind: reflection.ReflectionRaw,
			Context: reflection.ContextHTML,
		},
		Tech:   TechHints{BackendLanguage: "ASP.NET"},
		Budget: 80,
	})
	foundWin := false
	for _, p := range result.Payloads {
		if p.Family == "command_injection" && strings.Contains(strings.ToLower(p.Value), "dir") {
			foundWin = true
		}
	}
	if !foundWin {
		t.Fatalf("expected windows command payload, got %+v", result.Payloads)
	}
}

func TestWAFEvasionVariantsGenerated(t *testing.T) {
	result := Generate(Input{
		Profile: reflection.ReflectionProfile{
			CanaryValue: "akca11119z", ReflectionKind: reflection.ReflectionRaw,
			Context: reflection.ContextHTML,
		},
		Tech:   TechHints{Database: "mysql"},
		WAF:    WAFHints{Vendor: "Cloudflare", AllowEvasion: true},
		Budget: 200,
	})
	adapted := 0
	for _, p := range result.Payloads {
		if p.WAFAdapted {
			adapted++
			if p.WAFVendor == "" || p.Encoding == "none" || p.Encoding == "" {
				t.Fatalf("waf-adapted payload missing metadata: %+v", p)
			}
		}
	}
	if adapted == 0 {
		t.Fatal("expected at least one WAF-adapted payload variant")
	}
}

func TestWAFEvasionRequiresExplicitOptIn(t *testing.T) {
	result := Generate(Input{
		Profile: reflection.ReflectionProfile{CanaryValue: "akca11119z", ReflectionKind: reflection.ReflectionRaw, Context: reflection.ContextHTML},
		WAF:     WAFHints{Vendor: "Cloudflare"}, Budget: 200,
	})
	for _, p := range result.Payloads {
		if p.WAFAdapted {
			t.Fatal("WAF evasion payload must require explicit opt-in")
		}
	}
}

func TestNoWAFNoAdaptedVariants(t *testing.T) {
	result := Generate(Input{
		Profile: reflection.ReflectionProfile{
			CanaryValue: "akca11119z", ReflectionKind: reflection.ReflectionRaw,
			Context: reflection.ContextHTML,
		},
		Tech:   TechHints{Database: "mysql"},
		Budget: 200,
	})
	for _, p := range result.Payloads {
		if p.WAFAdapted {
			t.Fatal("no WAF detected, should not produce adapted variants")
		}
	}
}

func TestXSSPayloadsWhenReflectionRemoved(t *testing.T) {
	result := Generate(Input{
		Profile: reflection.ReflectionProfile{
			CanaryValue: "akca11119z", ReflectionKind: reflection.ReflectionRemoved,
			Context: reflection.ContextUnknown,
		},
		Tech:   TechHints{},
		Budget: -1,
	})
	found := false
	for _, p := range result.Payloads {
		if p.Family == "xss" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected xss payloads even when reflection is removed")
	}
}

func TestPgSleepAlwaysInSQLiPayloads(t *testing.T) {
	result := Generate(Input{
		Profile: reflection.ReflectionProfile{
			CanaryValue: "akca11119z", ReflectionKind: reflection.ReflectionRaw,
			Context: reflection.ContextHTML,
		},
		Tech:   TechHints{Database: "mysql"},
		Budget: -1,
	})
	found := false
	for _, p := range result.Payloads {
		if p.Family == "sqli" && strings.Contains(strings.ToLower(p.Value), "pg_sleep") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected pg_sleep payloads even when mysql is fingerprinted")
	}
}

func TestNegativeControlDoesNotConsumeBudget(t *testing.T) {
	profile := reflection.ReflectionProfile{
		EndpointURL: "http://example.com/search", Parameter: "q",
		CanaryValue: "akca11119z", ReflectionKind: reflection.ReflectionRaw,
		Context: reflection.ContextHTML, QuoteType: "none", Stable: true,
	}
	result := Generate(Input{
		Profile: profile,
		Tech:    TechHints{BackendLanguage: "php", Database: "mysql"},
		Budget:  1,
	})
	if result.BudgetUsed > 1 {
		t.Fatalf("budget limit is 1, but used %d", result.BudgetUsed)
	}
	var hasCanary, hasNegative bool
	for _, p := range result.Payloads {
		if p.Variant == "canary" {
			hasCanary = true
		}
		if p.Variant == "negative" {
			hasNegative = true
		}
	}
	if !hasCanary || !hasNegative {
		t.Fatalf("expected control/negative control to be present even with tight budget")
	}
}

func TestSOAPXXEPayloadValidity(t *testing.T) {
	payloads := xxePayloads("")
	var foundSOAP bool
	for _, p := range payloads {
		if p.Variant == "soap_xxe" {
			foundSOAP = true
			// DOCTYPE must appear before soap:Envelope element
			idxDocType := strings.Index(p.Value, "<!DOCTYPE")
			idxEnvelope := strings.Index(p.Value, "<soap:Envelope")
			if idxDocType < 0 || idxEnvelope < 0 || idxDocType > idxEnvelope {
				t.Fatalf("SOAP XXE payload is malformed: DOCTYPE must appear before root element. Payload: %s", p.Value)
			}
		}
	}
	if !foundSOAP {
		t.Fatal("soap_xxe payload not found")
	}
}

func TestUnknownTechNoSQLiEnabled(t *testing.T) {
	// JSON ContentType should enable NoSQLi when tech is unknown
	resultJSON := Generate(Input{
		Profile: reflection.ReflectionProfile{
			ContentType: "application/json",
		},
		Tech:   TechHints{},
		Budget: 100,
	})
	foundNoSQL := false
	for _, p := range resultJSON.Payloads {
		if p.Family == "nosql" {
			foundNoSQL = true
			break
		}
	}
	if !foundNoSQL {
		t.Fatal("expected NoSQLi payloads to be generated for unknown tech stack with JSON content type")
	}

	// Plain HTML Form ContentType should skip NoSQLi to reduce FPs/budget waste
	resultForm := Generate(Input{
		Profile: reflection.ReflectionProfile{
			ContentType: "application/x-www-form-urlencoded",
		},
		Tech:   TechHints{},
		Budget: 100,
	})
	for _, p := range resultForm.Payloads {
		if p.Family == "nosql" {
			t.Fatal("NoSQLi should be disabled for unknown tech stack with form content type to prevent budget waste/FPs")
		}
	}
}

func TestSQLiPayloadsIncludeXORBooleanAndTimingFamilies(t *testing.T) {
	payloads := sqliPayloads(reflection.ReflectionProfile{Context: reflection.ContextHTML}, TechHints{Database: "mysql"})
	foundTiming := false
	for _, payload := range payloads {
		switch payload.Variant {
		case "mysql_xor_if_sleep":
			foundTiming = payload.Value == `0'XOR(if(now()=sysdate(),sleep(6),0))XOR'Z`
		}
	}
	if !foundTiming {
		t.Fatal("missing XOR timing SQLi template")
	}
}

func TestGeneratedControlsAreDeterministicAndTargetSpecific(t *testing.T) {
	base := reflection.ReflectionProfile{
		ScanID: "scan-a", EndpointURL: "https://example.com/search", Method: "GET",
		Parameter: "q", ParameterLocation: "query", Context: reflection.ContextHTML,
	}
	first := Generate(Input{Profile: base, Budget: 5})
	second := Generate(Input{Profile: base, Budget: 5})
	otherProfile := base
	otherProfile.Parameter = "page"
	other := Generate(Input{Profile: otherProfile, Budget: 5})
	controlValue := func(result GenerationResult, variant string) string {
		for _, payload := range result.Payloads {
			if payload.Family == "control" && payload.Variant == variant {
				return payload.Value
			}
		}
		return ""
	}
	if got, want := controlValue(first, "canary"), controlValue(second, "canary"); got == "" || got != want {
		t.Fatalf("control must be non-empty and deterministic: %q != %q", got, want)
	}
	if controlValue(first, "canary") == controlValue(other, "canary") {
		t.Fatal("control must change with target parameter identity")
	}
	if controlValue(first, "negative") == controlValue(other, "negative") {
		t.Fatal("negative control must change with target parameter identity")
	}
}

func TestBalancedBudgetCoversEnabledFamilies(t *testing.T) {
	result := Generate(Input{
		Profile: reflection.ReflectionProfile{
			ScanID: "scan-a", EndpointURL: "https://example.com/api/search", Parameter: "q",
			ParameterLocation: "json", ContentType: "application/json", Context: reflection.ContextJSON,
			ReflectionKind: reflection.ReflectionRaw, Stable: true,
		},
		Budget: 15,
	})
	families := map[string]bool{}
	for _, payload := range result.Payloads {
		if payload.Family != "control" {
			families[payload.Family] = true
		}
	}
	for _, family := range []string{"xss", "sqli", "ssti", "command_injection", "nosql"} {
		if !families[family] {
			t.Fatalf("balanced budget starved %s; selected families: %v", family, families)
		}
	}
	if result.BudgetUsed > result.BudgetLimit {
		t.Fatalf("balanced selection exceeded budget: %d > %d", result.BudgetUsed, result.BudgetLimit)
	}
}

func TestSemanticDedupePreservesDistinctPayloadShapes(t *testing.T) {
	payloads := []Payload{
		{Value: `<img src=x onerror=alert(1)>`, VulnClass: "xss", Family: "xss", ExpectedSignal: "dom_mutation", Encoding: "none"},
		{Value: `<svg onload=alert(1)>`, VulnClass: "xss", Family: "xss", ExpectedSignal: "dom_mutation", Encoding: "none"},
	}
	for i := range payloads {
		payloads[i].SemanticKey = semanticKey(payloads[i])
	}
	if got := semanticDedupe(payloads); len(got) != 2 {
		t.Fatalf("distinct executable shapes must survive dedupe, got %d", len(got))
	}
}

func TestBlockedCharactersFilterIncompatiblePayloads(t *testing.T) {
	result := Generate(Input{
		Profile: reflection.ReflectionProfile{
			ScanID: "scan-a", EndpointURL: "https://example.com/search", Parameter: "q",
			Context: reflection.ContextHTML, ReflectionKind: reflection.ReflectionPartial,
			BlockedChars: []string{"<", ">"},
		},
		Budget: -1,
	})
	for _, payload := range result.Payloads {
		if payload.IsControl || payload.IsNegativeControl {
			continue
		}
		if strings.ContainsAny(payload.Value, "<>") {
			t.Fatalf("payload contains a target-blocked character: %+v", payload)
		}
	}
}

func TestCatalogAvoidsStaticBooleanAndPreEncodedSQLi(t *testing.T) {
	for _, payload := range sqliPayloads(reflection.ReflectionProfile{}, TechHints{Database: "mysql"}) {
		lower := strings.ToLower(payload.Value)
		if strings.HasPrefix(strings.ToLower(payload.ExpectedSignal), "content_change") &&
			(strings.Contains(lower, "1=1") || strings.Contains(lower, "'1'='2'")) {
			t.Fatalf("static boolean operand leaked into generator catalog: %q", payload.Value)
		}
		if strings.Contains(lower, "%20") || strings.Contains(lower, "%2c") {
			t.Fatalf("pre-encoded SQLi payload would be double encoded: %q", payload.Value)
		}
	}
}

func TestSSTICatalogUsesNonDestructiveEvaluation(t *testing.T) {
	for _, framework := range []string{"jinja", "twig", "freemarker"} {
		for _, payload := range sstiPayloads(reflection.ReflectionProfile{}, TechHints{Framework: framework}) {
			lower := strings.ToLower(payload.Value)
			for _, dangerous := range []string{"popen", "system", "exec", "subclasses", "runtime"} {
				if strings.Contains(lower, dangerous) {
					t.Fatalf("%s catalog contains execution primitive %q in %q", framework, dangerous, payload.Value)
				}
			}
		}
	}
}

func TestWAFGenerationIsDeterministic(t *testing.T) {
	in := Input{
		Profile: reflection.ReflectionProfile{
			ScanID: "scan-a", EndpointURL: "https://example.com/search", Parameter: "q",
			ParameterLocation: "query", Context: reflection.ContextHTML,
		},
		Tech:   TechHints{Database: "mysql"},
		WAF:    WAFHints{Vendor: "Cloudflare", AllowEvasion: true},
		Budget: 50,
	}
	first := Generate(in)
	second := Generate(in)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("identical input must produce identical ranked payloads")
	}
}

func TestWAFAdaptedPayloadsKeepOriginalPartnerUnderBudget(t *testing.T) {
	result := Generate(Input{
		Profile: reflection.ReflectionProfile{
			ScanID: "scan-a", EndpointURL: "https://example.com/search", Parameter: "q",
			ParameterLocation: "body", Context: reflection.ContextHTML,
		},
		Tech: TechHints{Database: "mysql"},
		WAF:  WAFHints{Vendor: "Cloudflare", AllowEvasion: true},
		// Enough for one paired offensive probe, not enough for standalone adapted
		// coverage across many families.
		Budget: 4,
	})
	originalByBase := map[string]bool{}
	for _, payload := range result.Payloads {
		if payload.IsControl || payload.IsNegativeControl || payload.WAFAdapted {
			continue
		}
		originalByBase[baseVariantKey(payload)] = true
	}
	for _, payload := range result.Payloads {
		if payload.WAFAdapted && !originalByBase[baseVariantKey(payload)] {
			t.Fatalf("WAF-adapted payload selected without original partner: %+v", payload)
		}
	}
}

func TestWAFLearningPrioritizesSuccessfulTechnique(t *testing.T) {
	result := Generate(Input{
		Profile: reflection.ReflectionProfile{
			ScanID: "scan-a", EndpointURL: "https://example.com/search", Parameter: "q",
			ParameterLocation: "body", Context: reflection.ContextHTML,
		},
		Tech: TechHints{Database: "mysql"},
		WAF: WAFHints{
			Vendor:              "Cloudflare",
			AllowEvasion:        true,
			PreferredTechniques: []string{"double_url", "unicode"},
		},
		Budget: -1,
	})
	firstAdapted := Payload{}
	for _, payload := range result.Payloads {
		if payload.WAFAdapted {
			firstAdapted = payload
			break
		}
	}
	if firstAdapted.Encoding != "double_url" && firstAdapted.Encoding != "unicode_url" {
		t.Fatalf("learned double_url technique was not prioritized, first adapted=%+v", firstAdapted)
	}
	if !strings.Contains(firstAdapted.SelectionReason, "WAF learning") {
		t.Fatalf("learned priority should be visible in selection reason: %q", firstAdapted.SelectionReason)
	}
}

func TestWAFContextAwareMutations(t *testing.T) {
	// In JSON context, XSS payloads should use unicode or json_unicode escaping, not raw HTML entities
	jsonResult := Generate(Input{
		Profile: reflection.ReflectionProfile{
			ScanID: "scan-json", EndpointURL: "https://example.com/api", Parameter: "name",
			Context: reflection.ContextJSON, ParameterLocation: "json",
		},
		WAF:    WAFHints{Vendor: "Cloudflare", AllowEvasion: true},
		Budget: -1,
	})
	for _, p := range jsonResult.Payloads {
		if p.WAFAdapted && p.Family == "xss" && !p.IsNegativeControl {
			if p.Encoding == "html_entity" {
				t.Fatalf("HTML entities should not be generated in JSON context: %+v", p)
			}
		}
	}
}

func TestWAFMutatedNegativeControls(t *testing.T) {
	result := Generate(Input{
		Profile: reflection.ReflectionProfile{
			ScanID: "scan-nc", EndpointURL: "https://example.com/item", Parameter: "id",
			Context: reflection.ContextHTML, ParameterLocation: "body",
		},
		Tech:   TechHints{Database: "mysql"},
		WAF:    WAFHints{Vendor: "Cloudflare", AllowEvasion: true},
		Budget: -1,
	})
	hasAdaptedOffensive := false
	hasAdaptedNegative := false
	for _, p := range result.Payloads {
		if p.WAFAdapted {
			if p.IsNegativeControl {
				hasAdaptedNegative = true
				if p.ControlFor == "" {
					t.Fatalf("adapted negative control must specify ControlFor: %+v", p)
				}
				if p.Encoding == "none" || p.Encoding == "" {
					t.Fatalf("adapted negative control must retain encoding: %+v", p)
				}
			} else {
				hasAdaptedOffensive = true
			}
		}
	}
	if !hasAdaptedOffensive {
		t.Fatal("expected at least one adapted offensive payload")
	}
	if !hasAdaptedNegative {
		t.Fatal("expected at least one adapted negative control payload")
	}
}

func TestQueryWAFEncodingAccountsForTransportLayer(t *testing.T) {
	original := `' OR 11=11-- -`
	doubleEncoded := wafintelValueForTest(original, "double_url")
	value, encoding := adjustWAFForTransport(original, doubleEncoded, "double_url", "query")
	if encoding != "double_url" || !strings.Contains(value, "%27") || strings.Contains(value, "%2527") {
		t.Fatalf("query transport must receive one pre-encoding layer, got %q (%s)", value, encoding)
	}
	if value, encoding := adjustWAFForTransport(original, "pre-encoded", "url", "query"); value != "" || encoding != "" {
		t.Fatalf("single URL clone duplicates normal query transport: %q (%s)", value, encoding)
	}
}

func wafintelValueForTest(value, encoding string) string {
	for _, variant := range wafVariantsForPayload(value, "sqli", "Cloudflare", reflection.ContextUnknown) {
		if variant.enc == encoding {
			return variant.value
		}
	}
	return ""
}

func TestDatabaseFingerprintRanksMatchingTimingFamily(t *testing.T) {
	result := Generate(Input{
		Profile: reflection.ReflectionProfile{
			ScanID: "scan-a", EndpointURL: "https://example.com/search", Parameter: "q",
			Context: reflection.ContextHTML, ReflectionKind: reflection.ReflectionRaw,
		},
		Tech:   TechHints{Database: "postgresql"},
		Learn:  LearningProfile{Blocked: []string{"xss", "ssti", "command_injection", "nosql"}},
		Budget: 3,
	})
	foundPostgres := false
	for _, payload := range result.Payloads {
		if payload.Family == "sqli" && strings.Contains(strings.ToLower(payload.Value), "pg_sleep") {
			foundPostgres = true
		}
	}
	if !foundPostgres {
		t.Fatalf("tight SQLi budget did not prioritize matching PostgreSQL probe: %+v", result.Payloads)
	}
}

func TestGroupBPayloadsReceiveCompleteMetadata(t *testing.T) {
	for _, family := range []string{"ssrf", "lfi", "xxe"} {
		payloads := GenerateGroupB(family, "https://callback.example/", WAFHints{})
		if len(payloads) == 0 {
			t.Fatalf("missing %s payloads", family)
		}
		for _, payload := range payloads {
			if payload.SemanticKey == "" || payload.VerificationStrategy == "" ||
				payload.SelectionReason == "" || payload.Encoding == "" || payload.BudgetCost <= 0 {
				t.Fatalf("incomplete %s metadata: %+v", family, payload)
			}
		}
	}
}

func TestGeneratedPayloadsReceivePlannerV2Metadata(t *testing.T) {
	result := Generate(Input{
		Profile: reflection.ReflectionProfile{
			ScanID: "scan-a", EndpointURL: "https://example.com/api/search", Method: "POST",
			Parameter: "q", ParameterLocation: "json", ContentType: "application/json",
			Context: reflection.ContextJSON, ReflectionKind: reflection.ReflectionRaw,
		},
		Tech:   TechHints{Database: "postgresql"},
		Budget: 40,
	})
	if result.EstimatedRequests <= 0 || result.Shadow.LegacyPayloads != len(result.Payloads) {
		t.Fatalf("missing planner estimates/shadow metrics: %+v", result)
	}
	if len(result.TestCases) == 0 || result.Shadow.SQLiTestCases == 0 {
		t.Fatalf("SQLi shadow test cases were not generated: %+v", result.Shadow)
	}
	for _, payload := range result.Payloads {
		if payload.Technique == "" || payload.ProbeRole == "" || payload.EstimatedRequests <= 0 || payload.TransportEncoding == "" {
			t.Fatalf("payload missing planner v2 metadata: %+v", payload)
		}
	}
	for _, tc := range result.TestCases {
		if !tc.ShadowOnly || tc.EstimatedRequests <= 0 || len(tc.Payloads) == 0 {
			t.Fatalf("invalid shadow test case: %+v", tc)
		}
	}
}

func TestNoSQLPayloadGeneratorUsesCanonicalCatalog(t *testing.T) {
	result := Generate(Input{
		Profile: reflection.ReflectionProfile{
			EndpointURL: "https://example.com/login", Method: "POST", Parameter: "username",
			ParameterLocation: "json", ContentType: "application/json", Context: reflection.ContextJSON,
		},
		Learn:  LearningProfile{Blocked: []string{"xss", "sqli", "ssti", "command_injection"}},
		Budget: -1,
	})
	foundLoginBypass := false
	for _, payload := range result.Payloads {
		if payload.Family == "nosql" && payload.Variant == "json_login_bypass" && payload.TransportEncoding == "json" {
			foundLoginBypass = true
		}
	}
	if !foundLoginBypass {
		t.Fatalf("expected canonical NoSQL JSON login payload, got %+v", result.Payloads)
	}
}

func TestXSSXMLAndCommentContextsUseDedicatedPayloads(t *testing.T) {
	for _, tc := range []struct {
		ctx     reflection.ContextType
		variant string
	}{
		{reflection.ContextXML, "xml_cdata_breakout"},
		{reflection.ContextComment, "comment_breakout"},
	} {
		result := Generate(Input{
			Profile: reflection.ReflectionProfile{Context: tc.ctx, ReflectionKind: reflection.ReflectionRaw},
			Learn:   LearningProfile{Blocked: []string{"sqli", "ssti", "command_injection", "nosql"}},
			Budget:  -1,
		})
		found := false
		for _, payload := range result.Payloads {
			if payload.Family == "xss" && payload.Variant == tc.variant {
				found = true
			}
			if payload.Family == "xss" && strings.HasPrefix(payload.Variant, "poly_") {
				t.Fatalf("%s context should use dedicated payloads before polyglot fallback: %+v", tc.ctx, payload)
			}
		}
		if !found {
			t.Fatalf("missing %s payload for %s context", tc.variant, tc.ctx)
		}
	}
}
