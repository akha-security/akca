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
	calls     map[string]int
}

func (c *sqliTimingRecordClient) Do(_ context.Context, method, rawURL string, _ []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	u, _ := url.Parse(rawURL)
	payload := u.Query().Get("q")
	if c.calls != nil {
		c.calls[payload]++
	}
	return httpclient.RequestResponse{
		Request: httpclient.RequestRecord{Method: method, URL: rawURL, Headers: headers},
		Response: httpclient.ResponseRecord{
			StatusCode: 200, Body: "stable response", Duration: c.durations[payload],
			Headers: map[string]string{"Content-Type": "text/html"},
		},
	}, nil
}

func TestSQLiBaselineAndTimingSharedAcrossQueryParams(t *testing.T) {
	c := &groupBClient{responses: map[string]string{"__default__": "stable response"}}
	r := groupBRunner(t, c)
	first := ScanTarget{EndpointURL: "http://example.com/search?id=1&q=test", Method: "GET", Parameter: "q", Location: "query"}
	second := first
	second.Parameter = "id"
	if _, timingBase, ok, reason := r.stableSQLiBaselineAndTiming(context.Background(), first); !ok || len(timingBase.Samples) != 5 {
		t.Fatalf("first baseline failed: ok=%v samples=%d reason=%q", ok, len(timingBase.Samples), reason)
	}
	if _, timingBase, ok, reason := r.stableSQLiBaselineAndTiming(context.Background(), second); !ok || len(timingBase.Samples) != 5 {
		t.Fatalf("cached baseline failed: ok=%v samples=%d reason=%q", ok, len(timingBase.Samples), reason)
	}
	if c.calls != 5 {
		t.Fatalf("query params on same request shape should share SQLi baseline, got %d calls", c.calls)
	}
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
		if !sqliAdvancedSurfaceReady(target, payloads, config.DefaultScanConfig()) {
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
	target := ScanTarget{
		Parameter: "tracking_nonce", Location: "query",
		Payloads: payloadgen.GenerationResult{Tech: payloadgen.TechHints{Database: "postgres"}},
	}
	cfg := config.DefaultScanConfig()
	cfg.AllowedVulnerabilityClasses = []string{"sqli", "xss"}
	if !sqliAdvancedSurfaceReady(target, payloads, cfg) {
		t.Fatal("all discovered parameters must be eligible for advanced SQLi probes")
	}
	emptyParam := target
	emptyParam.Parameter = ""
	if sqliAdvancedSurfaceReady(emptyParam, nil, cfg) {
		t.Fatal("empty parameter must not be eligible for advanced SQLi probes")
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
	findings := r.runSQLiOOB(context.Background(), target)
	if len(findings) != 0 {
		t.Fatalf("expected no OOB SQLi finding before OAST callback, got %d", len(findings))
	}
}

func TestSQLiOOBRunsBeforeUnstableBaseline(t *testing.T) {
	oastURL := "http://abc123.oast.test"
	c := &dynamicBaselineClient{}
	cfg := config.DefaultScanConfig()
	cfg.EnableOAST = true
	var coverageEvents int
	r := NewRunner(
		"scan-sqli-oob-baseline", c, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil),
		&stubOASTClient{url: oastURL},
		func(eventType, _ string, payload map[string]interface{}) error {
			if eventType == "sqli_oast_probe_coverage" {
				if sent, _ := payload["probes_sent"].(int); sent > 0 {
					coverageEvents++
				}
			}
			return nil
		},
		cfg,
	)
	target := ScanTarget{EndpointURL: "http://example.com/search?q=test", Method: "GET", Parameter: "q", Location: "query"}
	if findings := r.runSQLi(context.Background(), target); len(findings) != 0 {
		t.Fatalf("unstable baseline should not produce SQLi findings without callback, got %d", len(findings))
	}
	if coverageEvents != 1 {
		t.Fatalf("expected SQLi OOB coverage before baseline skip, got %d events", coverageEvents)
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

func TestSQLiDynamicTimingPayloadsIncludeCrossDBFallbacks(t *testing.T) {
	payloads := sqliDynamicTimingPayloads(5, "")
	joined := ""
	for _, p := range payloads {
		joined += strings.ToLower(p.Value) + "\n"
	}
	for _, want := range []string{"sleep(5)", "pg_sleep(5)", "waitfor delay"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("dynamic timing payloads missing %q in:\n%s", want, joined)
		}
	}
}

func TestSQLiDynamicTimingPayloadsPrioritizeOracleHint(t *testing.T) {
	payloads := sqliDynamicTimingPayloads(5, "oracle")
	if len(payloads) == 0 || !strings.Contains(strings.ToLower(payloads[0].Value), "dbms_lock.sleep") {
		t.Fatalf("oracle hint should prioritize DBMS_LOCK payload, got %+v", payloads)
	}
}

func TestSQLiClassicFallbackRunsWithoutGeneratedPayloads(t *testing.T) {
	cfg := config.DefaultScanConfig()
	payloads := appendSQLiClassicFallbacks(nil, cfg)
	if len(payloads) != 1 || payloads[0].Value != `'` || payloads[0].ExpectedSignal != "sql_error" {
		t.Fatalf("fast scan must retain a classic error-based SQLi probe, got %+v", payloads)
	}

	existing := []payloadgen.Payload{defaultPayload("sqli", "existing_error", `')`, "sql_error")}
	got := appendSQLiClassicFallbacks(existing, cfg)
	if len(got) != 1 || got[0].Variant != "existing_error" {
		t.Fatalf("existing classic SQLi payload must not be duplicated, got %+v", got)
	}
}

func TestSQLiTimingCoverageRunsBeforeUnstableBaseline(t *testing.T) {
	c := &dynamicBaselineClient{}
	cfg := config.DefaultScanConfig()
	var coverageEvents int
	var nonTimingCoverageEvents int
	r := NewRunner("scan-sqli-time-baseline", c, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil), nil,
		func(eventType, _ string, payload map[string]interface{}) error {
			if eventType == "sqli_timing_probe_coverage" {
				if delivered, _ := payload["payloads_delivered"].(int); delivered > 0 {
					coverageEvents++
				}
			}
			if eventType == "sqli_non_timing_probe_coverage" {
				errorDelivered, _ := payload["error_delivered"].(int)
				booleanDelivered, _ := payload["boolean_delivered"].(int)
				unionDelivered, _ := payload["union_delivered"].(int)
				if errorDelivered > 0 && booleanDelivered == 2 && unionDelivered > 0 {
					nonTimingCoverageEvents++
				}
			}
			return nil
		}, cfg)
	target := ScanTarget{EndpointURL: "http://example.com/search?q=test", Method: "GET", Parameter: "q", Location: "query"}
	if findings := r.runSQLi(context.Background(), target); len(findings) != 0 {
		t.Fatalf("unstable baseline should not produce SQLi findings, got %d", len(findings))
	}
	if coverageEvents == 0 {
		t.Fatal("expected SQLi timing coverage event before baseline skip")
	}
	if nonTimingCoverageEvents == 0 {
		t.Fatal("expected error, boolean and UNION probes before baseline skip")
	}
}

func TestSQLiBooleanAndUnionPathsReportDeliveredRequests(t *testing.T) {
	c := &groupBClient{responses: map[string]string{"__default__": "stable response"}}
	cfg := config.DefaultScanConfig()
	booleanDelivered := 0
	unionDelivered := 0
	r := NewRunner("scan-sqli-coverage", c, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil), nil,
		func(eventType, _ string, payload map[string]interface{}) error {
			switch eventType {
			case "sqli_boolean_probe_coverage":
				booleanDelivered, _ = payload["requests_delivered"].(int)
			case "sqli_union_probe_coverage":
				unionDelivered, _ = payload["requests_delivered"].(int)
			}
			return nil
		}, cfg)
	target := ScanTarget{EndpointURL: "http://example.com/search?q=test", Method: "GET", Parameter: "q", Location: "query"}
	baseline, err := r.probeForModule(context.Background(), "sqli", target, "akca-sqli-base")
	if err != nil {
		t.Fatal(err)
	}
	_ = r.runBooleanSQLi(context.Background(), target, baseline)
	_ = r.discoverSQLiColumnCount(context.Background(), target, baseline)
	if booleanDelivered == 0 || unionDelivered == 0 {
		t.Fatalf("SQLi paths did not deliver probes: boolean=%d union=%d", booleanDelivered, unionDelivered)
	}
	if unionDelivered > 20 {
		t.Fatalf("stable UNION discovery should avoid linear ORDER BY probing, delivered=%d", unionDelivered)
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

func TestSQLiTimingNegativeUsesSingleScout(t *testing.T) {
	payload := `0'XOR(if(now()=sysdate(),sleep(6),0))XOR'Z`
	zero := timingblind.SQLiMatchedZeroDelayPayload(payload, "mysql").Value
	baseline := timingblind.Calibrate([]int64{110, 120, 125, 115, 130})
	target := ScanTarget{EndpointURL: "http://example.com/search", Method: "GET", Parameter: "q", Location: "query"}
	client := &sqliTimingRecordClient{
		durations: map[string]time.Duration{payload: 120 * time.Millisecond, zero: 118 * time.Millisecond},
		calls:     map[string]int{},
	}
	r := groupBRunner(t, client)
	if ok, _, _, _ := r.sqliTimingVerified(context.Background(), target, payload, "mysql", baseline, 6); ok {
		t.Fatal("non-delayed timing payload must not verify")
	}
	if client.calls[payload] != 1 || client.calls[zero] != 0 {
		t.Fatalf("negative timing probe should stop after one scout, calls=%+v", client.calls)
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

// dynamicBaselineClient returns a different body on every call, simulating a
// page with CSRF tokens, timestamps or ads that change between requests.
type dynamicBaselineClient struct {
	callCount int
}

func (c *dynamicBaselineClient) Do(_ context.Context, method, rawURL string, _ []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	c.callCount++
	// Produce completely distinct content per call so body diff ratio > 0.35
	chars := []string{"A", "B", "C", "D", "E"}
	char := chars[(c.callCount-1)%len(chars)]
	body := strings.Repeat(char, 200) + fmt.Sprintf(" call-%d", c.callCount)
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Headers: headers},
		Response: httpclient.ResponseRecord{StatusCode: 200, Body: body, Headers: map[string]string{"Content-Type": "text/html"}},
	}, nil
}

func TestSQLiEmitsSkipOnUnstableBaseline(t *testing.T) {
	c := &dynamicBaselineClient{}
	cfg := config.DefaultScanConfig()
	var emitted []map[string]interface{}
	r := NewRunner("scan-baseline", c, scope.NewEngine(cfg), nil, verification.NewEngine(nil, nil), nil,
		func(eventType, _ string, payload map[string]interface{}) error {
			if eventType == "plugin_skipped" {
				emitted = append(emitted, payload)
			}
			return nil
		}, cfg)
	target := ScanTarget{EndpointURL: "http://example.com/search?q=test", Method: "GET", Parameter: "q", Location: "query"}
	findings := r.runSQLi(context.Background(), target)
	if len(findings) != 0 {
		t.Fatalf("unstable baseline should produce no findings, got %d", len(findings))
	}
	if len(emitted) == 0 {
		t.Fatal("expected a plugin_skipped event when baseline is unstable, got none")
	}
	reason, _ := emitted[0]["reason"].(string)
	if !strings.Contains(reason, "unstable baseline") && !strings.Contains(reason, "baseline probe failed") {
		t.Fatalf("skip reason should mention unstable baseline, got: %q", reason)
	}
	module, _ := emitted[0]["module"].(string)
	if module != "sqli" {
		t.Fatalf("expected module=sqli in skip event, got %q", module)
	}
}

func TestSQLiAdvancedRunsForNonAllowlistParam(t *testing.T) {
	// A parameter named "data" (not in the original allowlist) with reflection
	// should still trigger advanced probes (boolean blind, union, etc.)
	target := ScanTarget{
		EndpointURL: "http://example.com/api",
		Parameter:   "data",
		Location:    "query",
		Profile:     reflection.ReflectionProfile{ReflectionKind: "body_text"},
	}
	cfg := config.DefaultScanConfig()
	payloads := []payloadgen.Payload{{VulnClass: "sqli", Value: "' OR 1=1--"}}
	if !sqliAdvancedSurfaceReady(target, payloads, cfg) {
		t.Fatal("parameter with reflection should be allowed for advanced SQLi probes")
	}
	// JSON body parameter should also qualify
	jsonTarget := ScanTarget{
		EndpointURL: "http://example.com/api",
		Parameter:   "custom_field",
		Location:    "json",
	}
	if !sqliAdvancedSurfaceReady(jsonTarget, nil, cfg) {
		t.Fatal("JSON body parameter should be allowed for advanced SQLi probes")
	}
}

func TestPrioritizeSQLiPayloadsNumericAndDatabaseHint(t *testing.T) {
	basePayloads := []payloadgen.Payload{
		defaultPayload("sqli", "generic_quote", `'`, "sql_error"),
		defaultPayload("sqli", "mysql_extractvalue", `' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version())))-- -`, "sql_error"),
		defaultPayload("sqli", "pg_cast_error", `' AND (SELECT 1 FROM CAST((SELECT version()) AS INT))-- -`, "sql_error"),
		defaultPayload("sqli", "mssql_convert_error", `' AND 1=CONVERT(INT, @@version)-- -`, "sql_error"),
	}

	// 1. Numeric target should prepend numeric probes
	resNumeric := prioritizeSQLiPayloads(basePayloads, "", true, "42")
	if len(resNumeric) <= len(basePayloads) {
		t.Fatalf("expected numeric probes prepended, got %d", len(resNumeric))
	}
	if !strings.HasPrefix(resNumeric[0].Value, "42") {
		t.Fatalf("expected first payload to be numeric with value '42...', got %q", resNumeric[0].Value)
	}

	// 2. Database hint (e.g. postgres) should prioritize matching payloads
	resHint := prioritizeSQLiPayloads(basePayloads, "pg", false, "")
	if len(resHint) == 0 || !strings.Contains(resHint[0].Variant, "pg") {
		t.Fatalf("expected postgres payload first when dbHint='pg', got %q", resHint[0].Variant)
	}
}

func TestNativeTargetValueNestedJSON(t *testing.T) {
	target := ScanTarget{
		EndpointURL:  "https://example.com/api/users",
		Parameter:    "user.profile.age",
		Location:     "json",
		BodyTemplate: `{"user":{"profile":{"age":25,"name":"Alice"}}}`,
	}
	val := nativeTargetValue(target)
	if val != "25" {
		t.Fatalf("expected native value '25', got %q", val)
	}
	if !isNumericTargetValue(target) {
		t.Fatalf("expected age=25 to be classified as numeric target")
	}

	// Array nested target
	arrayTarget := ScanTarget{
		EndpointURL:  "https://example.com/api/items",
		Parameter:    "items.0.id",
		Location:     "json",
		BodyTemplate: `{"items":[{"id":999,"title":"Test"}]}`,
	}
	arrVal := nativeTargetValue(arrayTarget)
	if arrVal != "999" {
		t.Fatalf("expected native value '999', got %q", arrVal)
	}
	if !isNumericTargetValue(arrayTarget) {
		t.Fatalf("expected items.0.id=999 to be classified as numeric target")
	}
}

