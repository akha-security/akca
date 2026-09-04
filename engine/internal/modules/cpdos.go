package modules

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/verification"
)

var cpdosMethodHeaders = []string{
	"X-HTTP-Method-Override",
	"X-HTTP-Method",
	"X-Method-Override",
	"X-Original-Method",
}

func (r *Runner) runCPDoS(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("cpdos", target); !ok {
		r.emitSkip("cpdos", target, reason)
		return nil
	}

	if target.Method != "GET" {
		return nil
	}
	if _, err := url.Parse(target.EndpointURL); err != nil {
		return nil
	}

	baseline, baselineErr := r.cachedEmptyProbe(ctx, target)
	if baselineErr != nil || baseline.Response.StatusCode < 200 || baseline.Response.StatusCode >= 300 {
		return nil
	}

	var out []ModuleFinding

	for _, hName := range cpdosMethodHeaders {
		if ctx.Err() != nil {
			break
		}

		confirmed, pRR, cleanRR, ctrlRR := r.verifyCPDoSFlow(ctx, target, hName)
		if !confirmed {
			continue
		}

		// Double-confirmation loop with a 2nd round of unique cache busters
		round2, _, _, _ := r.verifyCPDoSFlow(ctx, target, hName)
		if !round2 {
			continue
		}

		signal := "cpdos_hmo"
		p := defaultPayload("cpdos", signal, hName+": AKCADOSTOKEN", signal)
		obs1 := r.observation("cpdos", target, verification.RoleStateBefore, 1, baseline)
		obs2 := r.observation("cpdos", target, verification.RolePositiveProbe, 1, pRR)
		obs3 := r.observation("cpdos", target, verification.RolePositiveReplay, 1, cleanRR)
		obs4 := r.observation("cpdos", target, verification.RoleNegativeControl, 1, ctrlRR)

		f := r.verifyAndBuildWithCandidate(ctx, "cpdos", target, p, baseline, cleanRR, signal, false, false, "", "", func(candidate *verification.Candidate) {
			candidate.RequestedProofType = verification.ProofContentEvidence
			candidate.NegativeControlSet = true
			candidate.NegativeControlOK = true
			candidate.Observations = append(candidate.Observations, obs1, obs2, obs3, obs4)
		})

		if f != nil {
			f.Severity = "high"
			f.Title = fmt.Sprintf("Cache-Poisoned Denial of Service (CPDoS) via %s", hName)
			f.Description = fmt.Sprintf("The intermediate caching layer/CDN stores backend error responses (HTTP %d) triggered by '%s' and serves them to subsequent clean requests, allowing unauthenticated denial of service against '%s'.", pRR.Response.StatusCode, hName, target.EndpointURL)
			r.recordFinding(ctx, &out, f, "cpdos", signal)
			return out
		}
	}

	return out
}

// verifyCPDoSFlow executes the strict 4-step verification state machine.
func (r *Runner) verifyCPDoSFlow(ctx context.Context, target ScanTarget, hName string) (bool, httpclient.RequestResponse, httpclient.RequestResponse, httpclient.RequestResponse) {
	var emptyRR httpclient.RequestResponse

	// -------------------------------------------------------------
	// Adım 1: Cache Buster ile Baseline (Clean Pre-Poison Check)
	// -------------------------------------------------------------
	cb1 := "akca_cpdos_" + randomProbeToken()
	testURL := appendQueryParam(target.EndpointURL, "akca_cb", cb1)
	if !r.scope.IsInScope(testURL) {
		return false, emptyRR, emptyRR, emptyRR
	}

	preRR, err := r.client.Do(ctx, "GET", testURL, nil, nil)
	if err != nil || preRR.Response.StatusCode < 200 || preRR.Response.StatusCode >= 300 {
		// If the endpoint with cache-buster naturally errors, we cannot test CPDoS on it
		return false, emptyRR, emptyRR, emptyRR
	}

	// -------------------------------------------------------------
	// Adım 2: Poison Probe (Inject Unexpected Override Header)
	// -------------------------------------------------------------
	poisonHeaders := map[string]string{hName: "AKCADOSTOKEN"}
	pRR, err := r.client.Do(ctx, "GET", testURL, nil, poisonHeaders)
	if err != nil {
		return false, emptyRR, emptyRR, emptyRR
	}

	// Must return an error status code
	isErrorStatus := pRR.Response.StatusCode == 400 || pRR.Response.StatusCode == 405 ||
		pRR.Response.StatusCode == 500 || pRR.Response.StatusCode == 501 || pRR.Response.StatusCode == 502
	if !isErrorStatus {
		return false, emptyRR, emptyRR, emptyRR
	}

	// 1. Önbellek Direktifleri Kontrolü (Cache-Control Inspection)
	// If the error response has no-store, private, max-age=0, or s-maxage=0, it is UNCACHEABLE -> Drop FP
	if isUncacheableResponse(pRR.Response.Headers) {
		return false, emptyRR, emptyRR, emptyRR
	}

	// -------------------------------------------------------------
	// Adım 3: Temiz Doğrulama / Poisoned Check (Request WITHOUT Header)
	// -------------------------------------------------------------
	cleanRR, err := r.client.Do(ctx, "GET", testURL, nil, nil)
	if err != nil {
		return false, emptyRR, emptyRR, emptyRR
	}

	// If clean request recovered to 200 OK -> Cache was NOT poisoned -> False Positive
	if cleanRR.Response.StatusCode >= 200 && cleanRR.Response.StatusCode < 300 {
		return false, emptyRR, emptyRR, emptyRR
	}

	// Clean request must match the error status code of the poison probe
	if cleanRR.Response.StatusCode != pRR.Response.StatusCode {
		return false, emptyRR, emptyRR, emptyRR
	}

	// Clean response must also NOT have uncacheable directives
	if isUncacheableResponse(cleanRR.Response.Headers) {
		return false, emptyRR, emptyRR, emptyRR
	}

	// 2. Cache Hit İspatı (Evidence of Caching)
	// Must exhibit Age > 0, CDN HIT status, or frozen timestamp/hash evidence
	if !hasCacheHitEvidence(cleanRR.Response.Headers, pRR.Response.Headers, pRR.Response.Body, cleanRR.Response.Body) {
		return false, emptyRR, emptyRR, emptyRR
	}

	// -------------------------------------------------------------
	// Adım 4: Kontrol Grubu / Negative Control (Independent Cache Buster)
	// -------------------------------------------------------------
	cb2 := "akca_cpdos_ctrl_" + randomProbeToken()
	ctrlURL := appendQueryParam(target.EndpointURL, "akca_cb", cb2)
	ctrlRR, err := r.client.Do(ctx, "GET", ctrlURL, nil, nil)
	if err != nil || ctrlRR.Response.StatusCode < 200 || ctrlRR.Response.StatusCode >= 300 {
		// If independent control is also returning 4xx/5xx, server is down globally or blocking scanner -> False Positive
		return false, emptyRR, emptyRR, emptyRR
	}

	return true, pRR, cleanRR, ctrlRR
}

// isUncacheableResponse checks if the response headers forbid intermediate caching.
func isUncacheableResponse(headers map[string]string) bool {
	cc := strings.ToLower(headerValue(headers, "Cache-Control"))
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") {
		return true
	}
	if strings.Contains(cc, "max-age=0") || strings.Contains(cc, "s-maxage=0") {
		return true
	}
	pragma := strings.ToLower(headerValue(headers, "Pragma"))
	if strings.Contains(pragma, "no-cache") && !strings.Contains(cc, "public") && !strings.Contains(cc, "max-age=") {
		return true
	}
	return false
}

// hasCacheHitEvidence verifies if a response was served from an intermediate cache layer.
func hasCacheHitEvidence(headers map[string]string, prevHeaders map[string]string, prevBody, currentBody string) bool {
	// 1. Age header > 0
	if ageStr := strings.TrimSpace(headerValue(headers, "Age")); ageStr != "" {
		if age, err := strconv.Atoi(ageStr); err == nil && age > 0 {
			return true
		}
	}

	// 2. Known CDN / Proxy Cache status headers
	cdnCacheHeaders := []string{
		"CF-Cache-Status",
		"X-Cache",
		"X-Cache-Lookup",
		"Akamai-Cache-Status",
		"X-Proxy-Cache",
		"Fastly-Cache-Status",
		"Cloudfront-Cache-Status",
		"X-Varnish",
		"X-Drupal-Cache",
		"X-Rack-Cache",
		"X-Cache-Hits",
		"X-Server-Cache",
	}
	for _, h := range cdnCacheHeaders {
		val := strings.ToLower(headerValue(headers, h))
		if strings.Contains(val, "hit") || strings.Contains(val, "cached") || strings.Contains(val, "revalidated") {
			return true
		}
	}

	// 3. Frozen dynamic headers (Date / Last-Modified) with identical body hash
	date1 := headerValue(headers, "Date")
	date2 := headerValue(prevHeaders, "Date")
	if date1 != "" && date1 == date2 && prevBody != "" && prevBody == currentBody {
		return true
	}

	return false
}

func appendQueryParam(rawURL, key, val string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		sep := "?"
		if strings.Contains(rawURL, "?") {
			sep = "&"
		}
		return rawURL + sep + key + "=" + val
	}
	q := parsed.Query()
	q.Set(key, val)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}
