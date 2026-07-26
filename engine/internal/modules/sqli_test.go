package modules

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/reflection"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/timingblind"
	"github.com/akha-security/akca/engine/internal/verification"
)

type sqliTimingRecordClient struct {
	durations map[string]time.Duration
}

func (c *sqliTimingRecordClient) Do(_ context.Context, method, rawURL string, _ []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	u, _ := url.Parse(rawURL)
	payload := u.Query().Get("q")
	return httpclient.RequestResponse{
		Request: httpclient.RequestRecord{Method: method, URL: rawURL, Headers: headers},
		Response: httpclient.ResponseRecord{
			StatusCode: 200, Body: "stable response", Duration: c.durations[payload],
			Headers: map[string]string{"Content-Type": "text/html"},
		},
	}, nil
}

func TestBooleanSQLiConfirmedRequiresFalseDelta(t *testing.T) {
	base := "items ok"
	falseBody := "items ok"
	trueBody := "many items listed"
	if !booleanSQLiConfirmed(trueBody, falseBody, base) {
		t.Fatal("expected true/false boolean confirmation")
	}
	if booleanSQLiConfirmed(trueBody, trueBody, base) {
		t.Fatal("expected identical true/false to be rejected")
	}
}

func TestBooleanSQLiConfirmedAllowsTrueBranchToMatchBaseline(t *testing.T) {
	base := "visible account row"
	trueBody := "visible account row"
	falseBody := "no matching rows"
	if !booleanSQLiConfirmed(trueBody, falseBody, base) {
		t.Fatal("expected true branch matching baseline to be accepted")
	}
}

func TestBooleanSQLiConfirmedRejectsTwoUnrelatedErrorPages(t *testing.T) {
	base := "normal search results"
	trueBody := "first unrelated validation error with a long body"
	falseBody := "second unrelated validation error with another body"
	if booleanSQLiConfirmed(trueBody, falseBody, base) {
		t.Fatal("two branches unrelated to baseline should be rejected")
	}
}

func TestBooleanPairRejectsReflectionAndWAFBranches(t *testing.T) {
	base := httpclient.ResponseRecord{StatusCode: 200, Body: "normal product list", Headers: map[string]string{"Content-Type": "text/html"}}
	truePayload := `XOR dynamic_true`
	falsePayload := `XOR dynamic_false`
	reflectedTrue := httpclient.ResponseRecord{StatusCode: 200, Body: "search " + truePayload, Headers: base.Headers}
	falseRR := httpclient.ResponseRecord{StatusCode: 200, Body: "no products", Headers: base.Headers}
	if booleanPairConfirmed(base, reflectedTrue, falseRR, truePayload, falsePayload) {
		t.Fatal("reflected XOR branch must not confirm SQLi")
	}
	wafTrue := httpclient.ResponseRecord{StatusCode: 200, Body: "AWS WAF Request blocked", Headers: base.Headers}
	if booleanPairConfirmed(base, wafTrue, falseRR, truePayload, falsePayload) {
		t.Fatal("WAF branch must not confirm SQLi")
	}
}

func TestBooleanPairRequiresOneBranchToMatchBaseline(t *testing.T) {
	base := httpclient.ResponseRecord{StatusCode: 200, Body: "normal product list", Headers: map[string]string{"Content-Type": "text/html"}}
	trueRR := httpclient.ResponseRecord{StatusCode: 200, Body: "normal product list", Headers: base.Headers}
	falseRR := httpclient.ResponseRecord{StatusCode: 200, Body: "no matching products", Headers: base.Headers}
	if !booleanPairConfirmed(base, trueRR, falseRR, `XOR dynamic_true`, `XOR dynamic_false`) {
		t.Fatal("stable baseline-equivalent true branch and distinct false branch should confirm")
	}
	unrelatedTrue := httpclient.ResponseRecord{StatusCode: 200, Body: "first random page", Headers: base.Headers}
	unrelatedFalse := httpclient.ResponseRecord{StatusCode: 200, Body: "second random page", Headers: base.Headers}
	if booleanPairConfirmed(base, unrelatedTrue, unrelatedFalse, "true", "false") {
		t.Fatal("two unrelated dynamic pages must not confirm boolean SQLi")
	}
}

func TestSQLiBooleanPairsUseDynamicOperands(t *testing.T) {
	target := ScanTarget{EndpointURL: "http://example.com/search", Parameter: "q", Location: "query"}
	first := sqliBooleanPairs("scan-a", target)
	second := sqliBooleanPairs("scan-b", target)
	if len(first) == 0 || len(second) != len(first) {
		t.Fatalf("unexpected boolean-pair sets: %d and %d", len(first), len(second))
	}
	for i, pair := range first {
		if strings.Contains(pair.trueVal, "7319") || strings.Contains(pair.falseVal, "7320") {
			t.Fatalf("fixed example operands leaked into runtime pair %d: %+v", i, pair)
		}
		if pair.trueVal == pair.falseVal {
			t.Fatalf("true/false payloads must be distinct for pair %d", i)
		}
		if pair.trueVal == second[i].trueVal || pair.falseVal == second[i].falseVal {
			t.Fatalf("pair %d did not change with scan identity", i)
		}
	}
}

func TestSQLiAdvancedSurfaceKeepsHeaderProbingEnabled(t *testing.T) {
	payloads := []payloadgen.Payload{{VulnClass: "sqli", Value: "' OR 1=1--"}}
	for _, header := range []string{
		"X-Forwarded-For", "X-Forwarded-Host", "Forwarded", "X-Real-IP", "Host", "User-Agent",
	} {
		target := ScanTarget{
			EndpointURL: "https://example.test/jobs/1", Parameter: header, Location: "header",
			Payloads: payloadgen.GenerationResult{
				Payloads: payloads,
				Tech:     payloadgen.TechHints{Database: "mssql"},
			},
		}
		if !sqliAdvancedSurfaceReady(target, payloads) {
			t.Fatalf("header %q must remain eligible for advanced SQLi probes", header)
		}
	}
}

func TestRunSQLiDoesNotReportStablePagesOnHeaderPayloads(t *testing.T) {
	for _, header := range []string{"X-Forwarded-For", "X-Forwarded-Host", "User-Agent"} {
		t.Run(header, func(t *testing.T) {
			target := ScanTarget{
				EndpointURL: "https://example.test/jobs/744000131613540", Method: "GET",
				Parameter: header, Location: "header",
				Payloads: payloadgen.GenerationResult{
					Tech: payloadgen.TechHints{Database: "mssql"},
					Payloads: []payloadgen.Payload{{
						VulnClass: "sqli", Value: "' OR '1'='1'-- -",
						ExpectedSignal: "boolean_pair", Variant: "boolean_single_quote",
					}},
				},
			}
			client := &groupBClient{responses: map[string]string{
				"__default__": "stable careers page",
			}}
			if findings := groupBRunner(t, client).runSQLi(context.Background(), target); len(findings) != 0 {
				t.Fatalf("forwarding header produced %d SQLi findings", len(findings))
			}
		})
	}
}

func TestSQLiAdvancedSurfaceRequiresSemanticParameterDespiteDatabaseFingerprint(t *testing.T) {
	payloads := []payloadgen.Payload{{VulnClass: "sqli", Value: "' OR 1=1--"}}
	unrelated := ScanTarget{
		Parameter: "tracking_nonce", Location: "query",
		Payloads: payloadgen.GenerationResult{Tech: payloadgen.TechHints{Database: "postgres"}},
	}
	if sqliAdvancedSurfaceReady(unrelated, payloads) {
		t.Fatal("global database fingerprint must not enable blind SQLi on an unrelated parameter")
	}
	relevant := unrelated
	relevant.Parameter = "product_id"
	if !sqliAdvancedSurfaceReady(relevant, nil) {
		t.Fatal("dynamic SQLi probes must not depend on persisted generated payloads")
	}
}

func TestBooleanBlindXORPairEndToEnd(t *testing.T) {
	target := ScanTarget{EndpointURL: "http://example.com/search", Method: "GET", Parameter: "q", Location: "query"}
	pairs := sqliBooleanPairs("scan-b", target)
	var truePayload, falsePayload string
	for _, pair := range pairs {
		if pair.variant == "boolean_xor_leading" {
			truePayload, falsePayload = pair.trueVal, pair.falseVal
			break
		}
	}
	c := &groupBClient{responses: map[string]string{
		"akca-sqli-base": "normal product list",
		truePayload:      "normal product list",
		falsePayload:     "no matching products",
		"__default__":    "normal product list",
	}}
	for _, pair := range pairs {
		if pair.variant == "boolean_xor_leading" {
			c.responses[pair.secondTrueVal] = "normal product list"
			c.responses[pair.secondFalseVal] = "no matching products"
			c.responses[booleanSyntaxControl(pair.trueVal)] = "normal product list"
		}
	}
	r := groupBRunner(t, c)
	baseline, _ := r.probe(context.Background(), target, "akca-sqli-base")
	findings := r.booleanBlindSQLiProbe(context.Background(), target, baseline)
	if len(findings) != 1 || findings[0].Evidence.Signal != "boolean_pair_confirmed" {
		t.Fatalf("expected one paired XOR SQLi finding, got %+v", findings)
	}
}

func TestBooleanBlindSinglePairIsInsufficient(t *testing.T) {
	target := ScanTarget{EndpointURL: "http://example.com/search", Method: "GET", Parameter: "q", Location: "query"}
	pairs := sqliBooleanPairs("scan-b", target)
	pair := pairs[3]
	c := &groupBClient{responses: map[string]string{
		"akca-sqli-base": "normal product list",
		pair.trueVal:     "normal product list",
		pair.falseVal:    "no matching products",
		"__default__":    "normal product list",
	}}
	r := groupBRunner(t, c)
	baseline, _ := r.probe(context.Background(), target, "akca-sqli-base")
	if findings := r.booleanBlindSQLiProbe(context.Background(), target, baseline); len(findings) != 0 {
		t.Fatalf("one boolean operand pair must not prove SQLi, got %d", len(findings))
	}
}

func TestBooleanBlindRejectsOppositeSecondOrientation(t *testing.T) {
	target := ScanTarget{EndpointURL: "http://example.com/search", Method: "GET", Parameter: "q", Location: "query"}
	pair := sqliBooleanPairs("scan-b", target)[3]
	c := &groupBClient{responses: map[string]string{
		"akca-sqli-base":                   "normal product list",
		pair.trueVal:                       "normal product list",
		pair.falseVal:                      "no matching products",
		pair.secondTrueVal:                 "no matching products",
		pair.secondFalseVal:                "normal product list",
		booleanSyntaxControl(pair.trueVal): "normal product list",
		"__default__":                      "normal product list",
	}}
	r := groupBRunner(t, c)
	baseline, _ := r.probe(context.Background(), target, "akca-sqli-base")
	if findings := r.booleanBlindSQLiProbe(context.Background(), target, baseline); len(findings) != 0 {
		t.Fatalf("opposite branch orientation must be rejected, got %d findings", len(findings))
	}
}

func TestUnionColumnDiscoveryRequiresBoundary(t *testing.T) {
	c := &groupBClient{responses: map[string]string{"__default__": "input ignored"}}
	r := groupBRunner(t, c)
	target := ScanTarget{EndpointURL: "http://example.com/search", Method: "GET", Parameter: "q"}
	baseline, _ := r.probe(context.Background(), target, "baseline")
	if got := r.discoverSQLiColumnCount(context.Background(), target, baseline); got != 0 {
		t.Fatalf("no success/error boundary must leave column count unknown, got %d", got)
	}
}

func TestPairedSSTIPayloadUsesDifferentProduct(t *testing.T) {
	p := payloadgen.Payload{Value: `{{11*13}}`, Variant: "jinja"}
	control, ok := pairedSSTIPayload(p)
	if !ok || control.Value != `{{13*17}}` {
		t.Fatalf("unexpected paired payload: %q", control.Value)
	}
	if !sstiSignalConfirmed(control, "value 221", "value", "math_evaluation") {
		t.Fatal("expected paired product to be independently confirmable")
	}
}

func TestDiscoverSQLiColumnCountOrderBy(t *testing.T) {
	c := &groupBClient{responses: map[string]string{
		"akca-sqli-base":   "ok",
		`' ORDER BY 1-- -`: "ok",
		`' ORDER BY 2-- -`: "ok",
		`' ORDER BY 3-- -`: "ok",
		`' ORDER BY 4-- -`: "mysql syntax error",
	}}
	r := groupBRunner(t, c)
	target := ScanTarget{EndpointURL: "http://example.com/search", Method: "GET", Parameter: "q"}
	baseline, _ := r.probe(context.Background(), target, "akca-sqli-base")
	got := r.discoverSQLiColumnCount(context.Background(), target, baseline)
	if got != 3 {
		t.Fatalf("expected 3 columns, got %d", got)
	}
}

func TestUnionSQLiWithColumnEnum(t *testing.T) {
	target := ScanTarget{EndpointURL: "http://example.com/search", Method: "GET", Parameter: "q"}
	primary := unionSentinelSet("scan-b", target, "primary")
	secondary := unionSentinelSet("scan-b", target, "secondary")
	unionPayload := buildUnionPayload(3, primary)
	secondaryPayload := buildUnionPayload(3, secondary)
	c := &groupBClient{responses: map[string]string{
		"akca-sqli-base":                     "ok",
		`' ORDER BY 1-- -`:                   "ok",
		`' ORDER BY 2-- -`:                   "ok",
		`' ORDER BY 3-- -`:                   "ok",
		`' ORDER BY 4-- -`:                   "mysql syntax error",
		unionPayload:                         "rows " + strings.Join(primary, " ") + " end",
		secondaryPayload:                     "rows " + strings.Join(secondary, " ") + " end",
		buildUnionLexicalControl(3, primary): "ordinary search results",
	}}
	r := groupBRunner(t, c)
	baseline, _ := r.probe(context.Background(), target, "akca-sqli-base")
	findings := r.unionSQLiProbe(context.Background(), target, baseline)
	if len(findings) == 0 {
		t.Fatal("expected union finding after column enumeration")
	}
}

func TestUnionSQLiRejectsCanonicalURLReflection(t *testing.T) {
	target := ScanTarget{EndpointURL: "http://example.com/search", Method: "GET", Parameter: "q"}
	primary := unionSentinelSet("scan-b", target, "primary")
	unionPayload := buildUnionPayload(3, primary)
	reflected := `<html><head><link rel="canonical" href="/search?q=` + url.QueryEscape(unionPayload) + `"></head><body>Search</body></html>`
	c := &groupBClient{responses: map[string]string{
		"akca-sqli-base":   "<html><body>Search</body></html>",
		`' ORDER BY 1-- -`: "ok",
		`' ORDER BY 2-- -`: "ok",
		`' ORDER BY 3-- -`: "ok",
		`' ORDER BY 4-- -`: "mysql syntax error",
		unionPayload:       reflected,
	}}
	r := groupBRunner(t, c)
	baseline, _ := r.probe(context.Background(), target, "akca-sqli-base")
	if findings := r.unionSQLiProbe(context.Background(), target, baseline); len(findings) != 0 {
		t.Fatalf("canonical URL reflection produced UNION SQLi: %+v", findings)
	}
}

func TestUnionSQLiRejectsPartialVisibleReflection(t *testing.T) {
	target := ScanTarget{EndpointURL: "http://example.com/search", Method: "GET", Parameter: "q"}
	primary := unionSentinelSet("scan-b", target, "primary")
	unionPayload := buildUnionPayload(3, primary)
	control := "AKCA_UNION_CONTROL_" + strings.Join(primary, "_")
	c := &groupBClient{responses: map[string]string{
		"akca-sqli-base":   "ordinary search results",
		`' ORDER BY 1-- -`: "ok",
		`' ORDER BY 2-- -`: "ok",
		`' ORDER BY 3-- -`: "ok",
		`' ORDER BY 4-- -`: "mysql syntax error",
		unionPayload:       "Search terms: " + strings.Join(primary, " "),
		control:            "Search terms: " + strings.Join(primary, " "),
	}}
	r := groupBRunner(t, c)
	baseline, _ := r.probe(context.Background(), target, "akca-sqli-base")
	if findings := r.unionSQLiProbe(context.Background(), target, baseline); len(findings) != 0 {
		t.Fatalf("partial visible reflection produced UNION SQLi: %+v", findings)
	}
}

func TestUnionSignalRejectsJSONPayloadEcho(t *testing.T) {
	payload := `' UNION SELECT 818533,828533,838533-- -`
	body := `{"query":` + fmt.Sprintf("%q", payload) + `,"results":[]}`
	if unionSignalConfirmed(payload, body, `{"results":[]}`) {
		t.Fatal("JSON payload echo must not confirm UNION SQLi")
	}
}

func TestUnionSignalRejectsReportedFifteenColumnHTMLAttributeReflection(t *testing.T) {
	payload := `' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,818533,828533,838533-- -`
	body := `<!DOCTYPE html><html><head>` +
		`<meta name="request-id" content="818533">` +
		`<link rel="canonical" href="/search?first=828533&amp;last=838533">` +
		`<script>window.scanValues=[818533,828533,838533]</script>` +
		`</head><body>Search results</body></html>`
	if unionSignalConfirmed(payload, body, "Search results") {
		t.Fatal("sentinels in meta/canonical/script contexts must not confirm UNION SQLi")
	}
}

func TestSQLiOOBPendingFinding(t *testing.T) {
	oastURL := "http://abc123.oast.test"
	payload := `' AND (SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,'abc123.oast.test','\\a')))-- -`
	c := &groupBClient{responses: map[string]string{
		"akca-sqli-base": "ok",
		payload:          "ok",
	}}
	cfg := config.DefaultScanConfig()
	cfg.EnableOAST = true
	r := NewRunner(
		"scan-sqli", c, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil),
		&stubOASTClient{url: oastURL},
		func(string, string, map[string]interface{}) error { return nil },
		cfg,
	)
	target := ScanTarget{EndpointURL: "http://example.com/search", Method: "GET", Parameter: "q"}
	baseline, _ := r.probe(context.Background(), target, "akca-sqli-base")
	findings := r.runSQLiOOB(context.Background(), target, baseline)
	if len(findings) != 0 {
		t.Fatalf("expected no OOB SQLi finding before OAST callback, got %d", len(findings))
	}
}

func TestSQLiTimingWithZeroControl(t *testing.T) {
	b := timingblind.Calibrate([]int64{120, 130, 110, 125, 115})
	sleep := 5
	delay := int64(b.AvgMs + float64(sleep*1000))
	zero := int64(b.AvgMs + 20)
	ok, _ := timingblind.VerifyProbeWithControl(delay, zero, b, sleep)
	if !ok {
		t.Fatal("expected timing with zero control to match")
	}
	ok, _ = timingblind.VerifyProbeWithControl(int64(b.AvgMs+200), zero, b, sleep)
	if ok {
		t.Fatal("expected insufficient delay to fail zero-control verification")
	}
}

func TestXORTimingRequiresMatchedZeroAndFalsePredicateControls(t *testing.T) {
	payload := `0'XOR(if(now()=sysdate(),sleep(6),0))XOR'Z`
	zero := `0'XOR(if(now()=sysdate(),SLEEP(0),0))XOR'Z`
	falsePredicate := `0'XOR(if(now()!=now(),sleep(6),0))XOR'Z`
	baseline := timingblind.Calibrate([]int64{110, 120, 125, 115, 130})
	target := ScanTarget{EndpointURL: "http://example.com/search", Method: "GET", Parameter: "q", Location: "query"}

	validClient := &sqliTimingRecordClient{durations: map[string]time.Duration{
		payload: 6120 * time.Millisecond, zero: 120 * time.Millisecond, falsePredicate: 125 * time.Millisecond,
	}}
	r := groupBRunner(t, validClient)
	if ok, _, _, _ := r.sqliTimingVerified(context.Background(), target, payload, "mysql", baseline, 6); !ok {
		t.Fatal("expected XOR timing to pass with fast matched controls")
	}

	wafDelayClient := &sqliTimingRecordClient{durations: map[string]time.Duration{
		payload: 6120 * time.Millisecond, zero: 120 * time.Millisecond, falsePredicate: 6100 * time.Millisecond,
	}}
	r = groupBRunner(t, wafDelayClient)
	if ok, _, _, _ := r.sqliTimingVerified(context.Background(), target, payload, "mysql", baseline, 6); ok {
		t.Fatal("payload-shape/WAF delay must fail when false XOR predicate is also slow")
	}
}

func TestXORPayloadKeepsSiblingQueryParameter(t *testing.T) {
	payload := `0'XOR(if(now()=sysdate(),sleep(6),0))XOR'Z`
	rawURL, _, _, err := reflection.BuildProbeRequestWithTemplate(
		"http://example.com/item?id=0&no=5", "GET", "id", "query", payload, "",
	)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("id") != payload || u.Query().Get("no") != "5" {
		t.Fatalf("payload or sibling parameter corrupted: %s", rawURL)
	}
}

func TestSQLiErrorRejectsGenericSyntaxError(t *testing.T) {
	if sqliErrorInBody("search parser syntax error near token", "normal search") {
		t.Fatal("generic parser syntax error must not confirm SQLi")
	}
	if !sqliErrorInBody("org.postgresql.util.PSQLException: syntax error at or near quote", "normal search") {
		t.Fatal("vendor-qualified database exception should confirm error-based SQLi")
	}
}

func TestSQLiPayloadGeneratorDoesNotEmitStaticBooleanPair(t *testing.T) {
	out := payloadgen.Generate(payloadgen.Input{
		Profile: reflection.ReflectionProfile{Context: reflection.ContextHTML},
		Tech:    payloadgen.TechHints{Database: "mysql"},
	})
	for _, p := range out.Payloads {
		if p.Variant == "boolean_false" || p.Variant == "boolean_true" ||
			p.Variant == "boolean_true_comment" || p.Variant == "boolean_numeric" {
			t.Fatalf("static boolean SQLi pair leaked from generator: %+v", p)
		}
	}
}

func TestModuleSignalConfirmedSQLiOOBRejected(t *testing.T) {
	p := defaultPayload("sqli", "mysql_load_file", "x", "oob_sqli")
	base := httpclient.ResponseRecord{Body: "ok", StatusCode: 200}
	probe := httpclient.ResponseRecord{Body: "ok", StatusCode: 200}
	if moduleSignalConfirmed("sqli", p, "oob_sqli", base, probe, false, "http://abc.oast.test") {
		t.Fatal("OOB SQLi should not confirm without callback")
	}
}

func TestStackedSQLiDifferentialWithoutTimingIsRejected(t *testing.T) {
	c := &groupBClient{responses: map[string]string{
		"akca-sqli-base":  "ok",
		`'; SELECT 1-- -`: "stack-one",
		`'; SELECT 2-- -`: "stack-two",
	}}
	cfg := config.DefaultScanConfig()
	r := NewRunner("scan-s", c, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil), nil,
		func(string, string, map[string]interface{}) error { return nil }, cfg)
	target := ScanTarget{EndpointURL: "http://example.com/search", Method: "GET", Parameter: "q"}
	baseline, _ := r.probe(context.Background(), target, "akca-sqli-base")
	findings := r.stackedSQLiProbe(context.Background(), target, baseline, timingblind.Baseline{}, 5, "mysql")
	if len(findings) != 0 {
		t.Fatalf("SELECT 1/2 body differences must not prove stacked SQLi: %+v", findings)
	}
}

// Ensure stubOASTClient satisfies OASTClient when used from sqli tests.
var _ OASTClient = (*stubOASTClient)(nil)

func TestPickSQLiAttemptPrefersDiff(t *testing.T) {
	base := "baseline"
	attempts := []InjectionAttempt{
		{Surface: "query", RR: httpclient.RequestResponse{Response: httpclient.ResponseRecord{Body: "baseline"}}},
		{Surface: "form", RR: httpclient.RequestResponse{Response: httpclient.ResponseRecord{Body: "changed-content-here"}}},
	}
	target := ScanTarget{Location: "query"}
	got := pickSQLiAttempt(attempts, base, target)
	if got.RR.Response.Body != "changed-content-here" {
		t.Fatalf("expected attempt with body diff, got %q", got.RR.Response.Body)
	}
}
