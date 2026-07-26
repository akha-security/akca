package bypass403

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	pathpkg "path"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

func (e *Engine) verifyCandidate(ctx context.Context, baseline Baseline, attempt Attempt,
	first httpclient.RequestResponse, preliminaryReason string) AttemptResult {
	result := AttemptResult{
		Attempt: attempt, Baseline: baseline, Request: first.Request, Response: first.Response,
		Reason: preliminaryReason,
	}
	if isNonResourceMethodAttempt(attempt) {
		result.Reason = "metadata_method_without_resource_access"
		return result
	}

	control := buildNegativeControl(baseline, attempt)
	result.ControlAttempt = &control
	if control.URL == "" || !e.scope.IsInScope(control.URL) {
		result.Reason = "negative_control_out_of_scope"
		return result
	}
	controlRR, err := e.client.Do(ctx, control.Method, control.URL, nil, control.Headers)
	if err != nil {
		result.Reason = "negative_control_failed"
		return result
	}
	result.ControlRequest = &controlRR.Request
	result.ControlResponse = &controlRR.Response
	if bodiesSimilar(first.Response.Body, controlRR.Response.Body) {
		result.Reason = "candidate_matches_negative_control"
		return result
	}
	if publicControl := buildPublicContentControl(baseline, attempt); publicControl.URL != "" &&
		e.scope.IsInScope(publicControl.URL) && publicControl.URL != baseline.URL {
		publicRR, publicErr := e.client.Do(ctx, publicControl.Method, publicControl.URL, nil, publicControl.Headers)
		if publicErr == nil {
			result.PublicControlRequest = &publicRR.Request
			result.PublicControlResponse = &publicRR.Response
			if bodiesSimilar(first.Response.Body, publicRR.Response.Body) {
				result.Reason = "candidate_matches_public_content"
				return result
			}
		}
	}
	if isStaticAssetResponse(first.Response.Headers) {
		result.Reason = "static_asset_without_protected_resource_evidence"
		return result
	}

	recheck, err := e.client.Do(ctx, attempt.Method, attempt.URL, nil, attempt.Headers)
	if err != nil {
		result.Reason = "candidate_recheck_failed"
		return result
	}
	result.RecheckRequest = &recheck.Request
	result.RecheckResponse = &recheck.Response
	recheckOK, _ := IsMeaningfulBypass(baseline, recheck.Response.StatusCode, recheck.Response.Body)
	if !recheckOK || recheck.Response.StatusCode != first.Response.StatusCode ||
		!bodiesSimilar(first.Response.Body, recheck.Response.Body) {
		result.Reason = "candidate_not_reproducible"
		return result
	}
	if looksLikeDeniedOrErrorPage(recheck.Response.Body) {
		result.Reason = "recheck_is_denial_or_challenge"
		return result
	}

	result.Succeeded = true
	result.Reason = "verified_ok_access"
	return result
}

func buildNegativeControl(baseline Baseline, attempt Attempt) Attempt {
	controlURL, controlPath := nonexistentSiblingURL(baseline.URL, attempt.Label)
	control := Attempt{
		Category: attempt.Category,
		Label:    "negative_control_" + attempt.Label,
		Method:   attempt.Method,
		URL:      baseline.URL,
		Headers:  cloneHeaders(attempt.Headers),
	}

	switch attempt.Category {
	case PathNormalization, EncodedPath, CaseVariant, TrailingSlashDot, MethodChange:
		control.URL = controlURL
	case MethodOverrideHeader:
		for key := range control.Headers {
			if strings.Contains(strings.ToLower(key), "method") {
				control.Headers[key] = "AKCA-CONTROL"
			}
		}
	case ForwardedURLHeader:
		setForwardedPathControl(control.Headers, controlPath)
	case IPTrustHeader:
		setIPControl(control.Headers)
	case ProtocolPortHeader:
		for key := range control.Headers {
			switch strings.ToLower(key) {
			case "x-forwarded-proto":
				control.Headers[key] = "http"
			case "x-forwarded-port":
				control.Headers[key] = "80"
			default:
				control.Headers[key] = "off"
			}
		}
	case ContentNegotiation:
		control.Headers = map[string]string{"Accept": "application/x-akca-negative-control"}
	case AuthHeaderPollution:
		setForwardedPathControl(control.Headers, controlPath)
		setIPControl(control.Headers)
		if _, ok := headerKey(control.Headers, "Authorization"); ok {
			control.Headers[headerKeyName(control.Headers, "Authorization")] = "Bearer akca.invalid.control"
		}
	case HopByHopStrip:
		control.Headers = map[string]string{
			"Connection":    "close",
			"Authorization": "Bearer akca.invalid.control",
		}
	case JWTBearerAbuse:
		control.Headers = map[string]string{"Authorization": "Bearer akca.invalid.control"}
	case BasicAuthAbuse:
		control.Headers = map[string]string{"Authorization": "Basic " + basicToken("akca-control", "invalid-control")}
	default:
		control.URL = controlURL
	}
	return control
}

func buildPublicContentControl(baseline Baseline, attempt Attempt) Attempt {
	u, err := url.Parse(baseline.URL)
	if err != nil {
		return Attempt{}
	}
	u.Path = "/"
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	control := Attempt{
		Category: attempt.Category,
		Label:    "public_content_control_" + attempt.Label,
		Method:   "GET",
		URL:      u.String(),
		Headers:  cloneHeaders(attempt.Headers),
	}
	setForwardedPathControl(control.Headers, "/")
	for key := range control.Headers {
		if strings.Contains(strings.ToLower(key), "method") {
			delete(control.Headers, key)
		}
	}
	return control
}

func nonexistentSiblingURL(rawURL, seed string) (string, string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", ""
	}
	sum := sha256.Sum256([]byte(rawURL + "|" + seed))
	token := hex.EncodeToString(sum[:6])
	dir := pathpkg.Dir(u.Path)
	if dir == "." {
		dir = "/"
	}
	controlPath := pathpkg.Join(dir, ".akca-access-control-"+token)
	if !strings.HasPrefix(controlPath, "/") {
		controlPath = "/" + controlPath
	}
	u.Path = controlPath
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), controlPath
}

func setForwardedPathControl(headers map[string]string, controlPath string) {
	for key := range headers {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "original-url") || strings.Contains(lower, "rewrite-url") ||
			strings.Contains(lower, "original-uri") {
			headers[key] = controlPath
		}
	}
}

func setIPControl(headers map[string]string) {
	for key := range headers {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "ip") || strings.Contains(lower, "forwarded-for") ||
			strings.Contains(lower, "real-ip") {
			headers[key] = "203.0.113.10"
		}
	}
}

func headerKey(headers map[string]string, name string) (string, bool) {
	for key := range headers {
		if strings.EqualFold(key, name) {
			return key, true
		}
	}
	return "", false
}

func headerKeyName(headers map[string]string, name string) string {
	if key, ok := headerKey(headers, name); ok {
		return key
	}
	return name
}

func isNonResourceMethodAttempt(attempt Attempt) bool {
	if attempt.Category != MethodChange {
		return false
	}
	switch strings.ToUpper(attempt.Method) {
	case "HEAD", "OPTIONS", "TRACE":
		return true
	default:
		return false
	}
}

func baselinesConsistent(first, second Baseline) bool {
	if first.StatusCode != second.StatusCode || !isAuthBlockedStatus(second.StatusCode) {
		return false
	}
	if first.StatusCode == 401 && !strings.EqualFold(first.AuthScheme.Kind, second.AuthScheme.Kind) {
		return false
	}
	return bodiesSimilar(first.Body, second.Body)
}

func isStaticAssetResponse(headers map[string]string) bool {
	contentType := strings.ToLower(headerValue(headers, "Content-Type"))
	return strings.HasPrefix(contentType, "image/") || strings.HasPrefix(contentType, "font/") ||
		strings.Contains(contentType, "text/css") || strings.Contains(contentType, "javascript")
}
