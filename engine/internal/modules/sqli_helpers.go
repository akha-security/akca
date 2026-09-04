package modules

import (
	"context"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/timingblind"
	"github.com/akha-security/akca/engine/internal/verification"
)

// sqliStrongKeywords are phrases that almost certainly indicate a real SQL
// error message when found in a response body.  A single match is sufficient.
var sqliStrongKeywords = []string{
	"you have an error in your sql",
	"mysql syntax error",
	"warning: mysqli",
	"unclosed quotation mark",
	"quoted string not properly terminated",
	"microsoft ole db provider",
	"odbc sql server driver",
	"pg::syntaxerror",
}

// sqliWeakKeywords may appear in non-SQL contexts (e.g. tech stack pages,
// marketing copy).  We require ≥2 distinct weak hits to count as evidence.
var sqliWeakKeywords = []string{
	"sql syntax", "mysql_", "mariadb", "sqlite", "postgresql", "pg_query",
	"ora-", "sqlstate", "syntax error near", "incorrect syntax near",
	"native client",
}

var sqliVendorErrorRe = regexp.MustCompile(`(?i)(sqlite3?\.OperationalError|ORA-\d{4,5}|PDOException.{0,160}SQLSTATE|java\.sql\.SQLException|org\.postgresql\.util\.PSQLException|pg_query\(|mysqli_sql_exception|mysql_fetch_(?:array|assoc|row)\(|SQLSTATE\[[0-9A-Z]+\])`)

type sqliBaselineSnapshot struct {
	baseline httpclient.RequestResponse
	timing   timingblind.Baseline
	ok       bool
	reason   string
}

type sqliBaselineCacheEntry struct {
	ready  chan struct{}
	result sqliBaselineSnapshot
}

// sqliGenericPageKeywords are tokens that indicate a generic info/error page
// (phpinfo, CMS about-page, WAF block page) rather than a real SQL error.
var sqliGenericPageKeywords = []string{
	"phpinfo()", "php credits", "waf", "access denied", "request blocked",
	"cloudflare", "incapsula", "sucuri", "akamai", "mod_security",
	"service unavailable",
}

var sqliWeakErrorGrammarRE = regexp.MustCompile(`(?i)(exception|stack trace|warning:|query (?:failed|error)|database error|at line \d+|in /[^ ]+ on line \d+)`)

func sqliErrorInBody(body, baseline string) bool {
	lower := strings.ToLower(body)
	base := strings.ToLower(baseline)

	// Only suppress if generic keywords are present AND no strong SQL error signature exists
	hasStrongSignal := sqliErrorRe.MatchString(lower)
	if !hasStrongSignal {
		for _, gk := range sqliGenericPageKeywords {
			if strings.Contains(lower, gk) && !strings.Contains(base, gk) {
				return false
			}
		}
	}

	// A single strong keyword is conclusive.
	for _, kw := range sqliStrongKeywords {
		if strings.Contains(lower, kw) && !strings.Contains(base, kw) {
			return true
		}
	}
	if sqliVendorErrorRe.MatchString(body) && !sqliVendorErrorRe.MatchString(baseline) {
		return true
	}

	// Weak keywords require ≥2 distinct matches.
	weakHits := 0
	for _, kw := range sqliWeakKeywords {
		if strings.Contains(lower, kw) && !strings.Contains(base, kw) {
			weakHits++
		}
	}
	if weakHits >= 2 && sqliWeakErrorGrammarRE.MatchString(body) {
		return true
	}

	// Do not fall back to a generic "syntax error" regex: template engines,
	// search parsers and application validators use the same phrase.
	return false
}

func (r *Runner) sqliBestAttempt(ctx context.Context, target ScanTarget, value, baselineBody string) (InjectionAttempt, bool) {
	attempts := r.injectionProbeAttemptsForModule(ctx, "sqli", target, value)
	if len(attempts) == 0 {
		return InjectionAttempt{}, false
	}
	return pickSQLiAttempt(attempts, baselineBody, target), true
}

// pickSQLiAttempt prefers SQL error evidence, then the native injection surface, then the strongest body delta.
func pickSQLiAttempt(attempts []InjectionAttempt, baselineBody string, target ScanTarget) InjectionAttempt {
	native := strings.ToLower(strings.TrimSpace(target.Location))
	if native == "" {
		native = strings.ToLower(strings.TrimSpace(target.Profile.ParameterLocation))
	}
	best := attempts[0]
	bestScore := -1.0
	for _, a := range attempts {
		body := a.RR.Response.Body
		if strings.TrimSpace(body) == "" {
			continue
		}
		surface := strings.ToLower(a.Surface)
		score := bodyDiffRatio(baselineBody, body)
		if sqliErrorInBody(body, baselineBody) {
			score += 0.5
		}
		if native != "" && strings.Contains(surface, native) {
			score += 0.02
		}
		if body != baselineBody {
			score += 0.01
		}
		if score > bestScore {
			bestScore = score
			best = a
		}
	}
	if bestScore < 0 {
		return attempts[0]
	}
	return best
}

func booleanSQLiConfirmed(trueBody, falseBody, baseline string) bool {
	// Normalize volatile fields so timestamps/UUIDs/CSRF tokens don't inflate diffs.
	normTrue := normalizeVolatileFields(trueBody)
	normFalse := normalizeVolatileFields(falseBody)
	normBase := normalizeVolatileFields(baseline)

	if normTrue == "" {
		return false
	}
	if normFalse != "" {
		if normTrue == normFalse {
			return false
		}
		// True and false bodies must differ significantly from each other.
		if bodyDiffRatio(normFalse, normTrue) < 0.03 {
			return false
		}
		// Either branch may match the normal response depending on how the
		// application embeds the predicate. Requiring only the false branch to
		// match loses valid numeric and existing-WHERE-clause cases.
		trueToBase := bodyDiffRatio(normBase, normTrue)
		falseToBase := bodyDiffRatio(normBase, normFalse)
		if trueToBase > 0.20 && falseToBase > 0.20 {
			return false
		}
		return true
	}
	if normTrue == normBase {
		return false
	}
	return bodyDiffRatio(normBase, normTrue) >= 0.04
}

func booleanPairConfirmed(baseline, trueRR, falseRR httpclient.ResponseRecord, truePayload, falsePayload string) bool {
	if baseline.StatusCode == 0 {
		return false
	}
	if isInfrastructureError(trueRR.StatusCode) || isInfrastructureError(falseRR.StatusCode) ||
		trueRR.StatusCode == 405 || falseRR.StatusCode == 405 || trueRR.StatusCode == 429 || falseRR.StatusCode == 429 {
		return false
	}
	if !usableBooleanSQLiResponse(trueRR) || !usableBooleanSQLiResponse(falseRR) {
		return false
	}
	return booleanSQLiConfirmed(trueRR.Body, falseRR.Body, baseline.Body)
}

func usableBooleanSQLiResponse(rr httpclient.ResponseRecord) bool {
	if strings.TrimSpace(rr.Body) == "" || sqliErrorRe.MatchString(rr.Body) {
		return false
	}
	if fp, matched := verification.MatchErrorFingerprint(rr.Body, rr.StatusCode, rr.Headers); matched {
		switch fp.Classification {
		case "waf_block", "generic_error", "login_redirect", "framework_error":
			return false
		}
	}
	lower := strings.ToLower(rr.Body)
	for _, marker := range []string{
		"access denied", "request blocked", "web application firewall", "attention required",
		"captcha", "checking your browser", "rate limit exceeded", "too many requests",
	} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	return true
}

func payloadReflectedAnyEncoding(payload, body, baseline string) bool {
	if strings.TrimSpace(payload) == "" {
		return false
	}
	forms := []string{payload, html.EscapeString(payload), url.QueryEscape(payload), url.PathEscape(payload)}
	for _, form := range forms {
		if form != "" && strings.Contains(body, form) && !strings.Contains(baseline, form) {
			return true
		}
	}
	unescapedBody := html.UnescapeString(body)
	unescapedBase := html.UnescapeString(baseline)
	if strings.Contains(unescapedBody, payload) && !strings.Contains(unescapedBase, payload) {
		return true
	}
	return false
}

func sqliBodiesEquivalent(left, right string) bool {
	left = normalizeVolatileFields(left)
	right = normalizeVolatileFields(right)
	return left == right || (left != "" && right != "" && bodyDiffRatio(left, right) <= 0.02)
}

func medianInt64(vals []int64) int64 {
	if len(vals) == 0 {
		return 0
	}
	cp := append([]int64(nil), vals...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	mid := len(cp) / 2
	if len(cp)%2 == 0 {
		return (cp[mid-1] + cp[mid]) / 2
	}
	return cp[mid]
}

func (r *Runner) stableSQLiBaselineAndTiming(ctx context.Context, target ScanTarget) (httpclient.RequestResponse, timingblind.Baseline, bool, string) {
	key := sqliBaselineCacheKey(target)
	r.sqliBaselineMu.Lock()
	if r.sqliBaselines == nil {
		r.sqliBaselines = make(map[string]*sqliBaselineCacheEntry)
	}
	if entry, ok := r.sqliBaselines[key]; ok {
		r.sqliBaselineMu.Unlock()
		select {
		case <-entry.ready:
			return entry.result.baseline, entry.result.timing, entry.result.ok, entry.result.reason
		case <-ctx.Done():
			return httpclient.RequestResponse{}, timingblind.Baseline{}, false, ctx.Err().Error()
		}
	}
	entry := &sqliBaselineCacheEntry{ready: make(chan struct{})}
	r.sqliBaselines[key] = entry
	r.sqliBaselineMu.Unlock()

	entry.result = r.collectSQLiBaselineAndTiming(ctx, target)
	close(entry.ready)
	return entry.result.baseline, entry.result.timing, entry.result.ok, entry.result.reason
}

func (r *Runner) collectSQLiBaselineAndTiming(ctx context.Context, target ScanTarget) sqliBaselineSnapshot {
	const samplesWanted = 5
	value := nativeTargetValue(target)
	samples := make([]int64, 0, samplesWanted)
	var first httpclient.RequestResponse
	haveFirst := false

	for i := 0; i < samplesWanted; i++ {
		if ctx.Err() != nil {
			return sqliBaselineSnapshot{ok: false, reason: ctx.Err().Error()}
		}
		start := time.Now()
		rr, err := r.probeForModule(ctx, "sqli", target, value)
		if err != nil {
			if !haveFirst && i == 0 {
				fallback, fallbackErr := r.cachedEmptyProbe(ctx, target)
				if fallbackErr != nil {
					return sqliBaselineSnapshot{ok: false, reason: "baseline probe failed on attempt 1: " + fallbackErr.Error()}
				}
				rr = fallback
			} else {
				break
			}
		}
		ms := rr.Response.Duration.Milliseconds()
		if ms <= 0 {
			ms = time.Since(start).Milliseconds()
		}
		samples = append(samples, ms)

		if !haveFirst {
			first = rr
			haveFirst = true
			continue
		}
		if rr.Response.StatusCode != first.Response.StatusCode {
			return sqliBaselineSnapshot{ok: false, reason: fmt.Sprintf(
				"unstable baseline: status code changed from %d to %d on attempt %d",
				first.Response.StatusCode, rr.Response.StatusCode, i+1)}
		}
		ratio := bodyDiffRatio(normalizeVolatileFields(first.Response.Body), normalizeVolatileFields(rr.Response.Body))
		if ratio > 0.85 {
			return sqliBaselineSnapshot{ok: false, reason: fmt.Sprintf(
				"unstable baseline: body diff ratio %.4f exceeds threshold 0.85 on attempt %d",
				ratio, i+1)}
		}
	}
	if !haveFirst {
		return sqliBaselineSnapshot{ok: false, reason: "baseline probe failed"}
	}
	return sqliBaselineSnapshot{baseline: first, timing: timingblind.Calibrate(samples), ok: true}
}

func sqliBaselineCacheKey(target ScanTarget) string {
	template := target.RequestTemplate
	if template.URL == "" {
		template.URL = target.EndpointURL
	}
	if template.Method == "" {
		template.Method = target.Method
	}
	if template.Body == "" {
		template.Body = target.BodyTemplate
	}
	if template.ContentType == "" {
		template.ContentType = target.Profile.ContentType
	}
	method := strings.ToUpper(strings.TrimSpace(template.Method))
	if method == "" {
		method = "GET"
	}
	location := strings.ToLower(strings.TrimSpace(target.Location))
	if location == "" {
		location = strings.ToLower(strings.TrimSpace(target.Profile.ParameterLocation))
	}
	if location == "" {
		location = "query"
	}
	parts := []string{
		method,
		location,
		template.URL,
		template.Body,
		template.ContentType,
		serializedRequestHeaders(template.Headers),
	}
	switch location {
	case "header", "cookie", "path":
		parts = append(parts, strings.ToLower(strings.TrimSpace(target.Parameter)))
	}
	return strings.Join(parts, "\x1f")
}

func serializedRequestHeaders(headers map[string]string) string {
	if len(headers) == 0 {
		return ""
	}
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return strings.ToLower(keys[i]) < strings.ToLower(keys[j])
	})
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, strings.ToLower(strings.TrimSpace(key))+"\x1e"+headers[key])
	}
	return strings.Join(parts, "\x1d")
}

func (r *Runner) sqliTimingMedianMs(ctx context.Context, target ScanTarget, payload string, samples int) (int64, []int64, int, int, bool) {
	if samples <= 0 {
		samples = 3
	}
	vals := make([]int64, 0, samples)
	status := 0
	delivered := 0
	for i := 0; i < samples; i++ {
		if ctx.Err() != nil {
			break
		}
		start := time.Now()
		attempts := r.injectionProbeAttemptsForModule(ctx, "sqli", target, payload)
		if len(attempts) == 0 {
			return 0, vals, status, delivered, false
		}
		delivered++
		attempt := pickSlowestAttempt(attempts)
		if !usableTimingSQLiResponse(attempt.RR.Response) {
			return 0, vals, status, delivered, false
		}
		if status == 0 {
			status = attempt.RR.Response.StatusCode
		} else if status != attempt.RR.Response.StatusCode {
			return 0, vals, status, delivered, false
		}
		ms := attempt.RR.Response.Duration.Milliseconds()
		if ms <= 0 {
			ms = time.Since(start).Milliseconds()
		}
		vals = append(vals, ms)
	}
	return medianInt64(vals), vals, status, delivered, len(vals) == samples
}

func (r *Runner) sqliTimingVerified(ctx context.Context, target ScanTarget, payload string, dbHint string,
	timingBase timingblind.Baseline, sleepSec int) (ok bool, delayMs int64, samples []int64, zeroSamples []int64) {
	var delaySamples []int64
	var delayStatus int
	var delayDelivered, zeroDelivered, falseDelivered int
	var seriesOK bool
	reason := "verified"
	defer func() {
		delivered := delayDelivered + zeroDelivered + falseDelivered
		if delivered > 0 && r.emit != nil {
			_ = r.emit("sqli_timing_probe_coverage", "SQLi timing probe coverage recorded", map[string]interface{}{
				"scan_id": r.scanID, "endpoint": target.EndpointURL, "parameter": target.Parameter,
				"payloads_delivered": delivered, "delay_samples": len(delaySamples),
				"zero_control_samples": len(zeroSamples), "verified": ok, "reason": reason,
				"db_hint": dbHint,
			})
		}
	}()
	delayMs, delaySamples, delayStatus, delayDelivered, seriesOK = r.sqliTimingMedianMs(ctx, target, payload, 1)
	if !seriesOK {
		reason = "delay_series_incomplete_or_unusable"
		return false, 0, delaySamples, nil
	}
	if !sqliTimingScoutPlausible(delayMs, timingBase, sleepSec) {
		reason = "delay_scout_within_baseline"
		return false, delayMs, delaySamples, nil
	}

	zeroPayload := timingblind.SQLiMatchedZeroDelayPayload(payload, dbHint)
	var zeroSamplesVal []int64
	zeroMs, zeroSamplesVal, zeroStatus, delivered, zeroOK := r.sqliTimingMedianMs(ctx, target, zeroPayload.Value, 1)
	zeroDelivered = delivered
	zeroSamples = zeroSamplesVal
	if !zeroOK || delayStatus != zeroStatus {
		reason = "zero_control_incomplete_or_status_mismatch"
		return false, delayMs, delaySamples, zeroSamplesVal
	}
	if !sqliTimingPairPlausible(delayMs, zeroMs, timingBase, sleepSec) {
		reason = "delay_not_plausible_against_zero_control"
		return false, delayMs, delaySamples, zeroSamplesVal
	}

	extraDelayMs, extraDelaySamples, extraDelayStatus, delivered, extraDelayOK := r.sqliTimingMedianMs(ctx, target, payload, 2)
	delayDelivered += delivered
	delaySamples = append(delaySamples, extraDelaySamples...)
	delayMs = medianInt64(delaySamples)
	if !extraDelayOK || extraDelayStatus != delayStatus || extraDelayMs == 0 {
		reason = "delay_series_incomplete_or_unusable"
		return false, delayMs, delaySamples, zeroSamplesVal
	}

	extraZeroMs, extraZeroSamples, extraZeroStatus, delivered, extraZeroOK := r.sqliTimingMedianMs(ctx, target, zeroPayload.Value, 2)
	zeroDelivered += delivered
	zeroSamplesVal = append(zeroSamplesVal, extraZeroSamples...)
	zeroSamples = zeroSamplesVal
	zeroMs = medianInt64(zeroSamplesVal)
	if !extraZeroOK || extraZeroStatus != zeroStatus || extraZeroMs == 0 {
		reason = "zero_control_incomplete_or_status_mismatch"
		return false, delayMs, delaySamples, zeroSamplesVal
	}

	ok, _ = timingblind.VerifyProbeWithControl(delayMs, zeroMs, timingBase, sleepSec)
	if !ok || timingDelayHitCount(delaySamples, zeroMs, timingBase, sleepSec) < 2 {
		reason = "delay_not_above_zero_control"
		return false, delayMs, delaySamples, zeroSamplesVal
	}
	if falseControl, hasFalseControl := timingblind.SQLiXORFalseConditionControl(payload); hasFalseControl {
		falseMs, falseSamples, falseStatus, delivered, falseOK := r.sqliTimingMedianMs(ctx, target, falseControl.Value, 3)
		falseDelivered = delivered
		zeroSamplesVal = append(zeroSamplesVal, falseSamples...)
		zeroSamples = zeroSamplesVal
		if !falseOK || falseStatus != delayStatus {
			reason = "false_predicate_control_incomplete_or_status_mismatch"
			return false, delayMs, delaySamples, zeroSamplesVal
		}
		if matched, _ := timingblind.VerifyProbeWithControl(delayMs, falseMs, timingBase, sleepSec); !matched {
			reason = "false_predicate_control_also_slow"
			return false, delayMs, delaySamples, zeroSamplesVal
		}
	}
	return ok, delayMs, delaySamples, zeroSamplesVal
}

func sqliTimingScoutPlausible(delayMs int64, baseline timingblind.Baseline, sleepSec int) bool {
	if sleepSec <= 0 || len(baseline.Samples) < 3 {
		return true
	}
	threshold := baseline.AvgMs + float64(sleepSec*1000)/3 - baseline.JitterMs*2 - 250
	return float64(delayMs) >= threshold
}

func sqliTimingPairPlausible(delayMs, zeroMs int64, baseline timingblind.Baseline, sleepSec int) bool {
	if sleepSec <= 0 || len(baseline.Samples) < 3 {
		return true
	}
	delayDelta := float64(delayMs) - float64(zeroMs)
	minDelta := float64(sleepSec*1000) * 0.45
	if minDelta < baseline.JitterMs*2+350 {
		minDelta = baseline.JitterMs*2 + 350
	}
	return delayDelta >= minDelta && float64(delayMs) >= baseline.AvgMs+float64(sleepSec*1000)*0.45
}

func usableTimingSQLiResponse(rr httpclient.ResponseRecord) bool {
	// For timing-based probes, the signal is response delay, not status code.
	// Only reject connection-level failures and CDN infrastructure errors.
	if rr.StatusCode == 0 {
		return false
	}
	if isInfrastructureError(rr.StatusCode) {
		return false
	}
	return true
}

func timingDelayHitCount(samples []int64, controlMs int64, baseline timingblind.Baseline, sleepSec int) int {
	hits := 0
	for _, sample := range samples {
		if ok, _ := timingblind.VerifyProbeWithControl(sample, controlMs, baseline, sleepSec); ok {
			hits++
		}
	}
	return hits
}

func oastHostFromURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return strings.TrimPrefix(strings.TrimPrefix(raw, "http://"), "https://")
	}
	return u.Hostname()
}

func (r *Runner) techDatabaseHint(endpointURL string) string {
	if r.db == nil {
		return ""
	}
	host := hostFromModuleURL(endpointURL)
	if host == "" {
		return ""
	}
	fp, err := r.db.GetTechFingerprint(r.scanID, host)
	if err != nil {
		return ""
	}
	return fp.Database
}

func hostFromModuleURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
