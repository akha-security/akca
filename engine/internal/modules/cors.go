package modules

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/verification"
)

func (r *Runner) runCORS(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("cors", target); !ok {
		r.emitSkip("cors", target, reason)
		return nil
	}
	if isStaticAssetURL(target.EndpointURL) {
		return nil
	}
	baseline, err := r.probeCORS(ctx, target, "")
	if err != nil {
		return nil
	}
	u, err := url.Parse(target.EndpointURL)
	if err != nil {
		return nil
	}
	probes := []struct{ origin, signal string }{
		{"https://evil.example", "origin_reflection"}, {"https://another-evil.example", "origin_reflection"},
		{"null", "null_origin"}, {"https://" + u.Hostname() + ".evil.example", "partial_origin_match"},
		{"https://evil" + u.Hostname(), "pre_domain_match"}, {"http://" + u.Hostname(), "protocol_downgrade"},
		{"https://" + strings.Replace(u.Hostname(), ".", "x", 1), "unquoted_regex_dot_bypass"},
		{"https://" + u.Hostname() + "_.evil.example", "special_char_bypass"},
	}
	var out []ModuleFinding
	for _, pr := range probes {
		if originURL, e := url.Parse(pr.origin); e == nil && strings.EqualFold(originURL.Scheme, u.Scheme) && strings.EqualFold(originURL.Host, u.Host) {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		rr, err := r.probeCORS(ctx, target, pr.origin)
		if err != nil {
			continue
		}
		if corsWildcardCredentials(rr.Response.Headers) {
			r.emitDiscovery("cors", target, "wildcard_credentials", "Wildcard ACAO with credentials is not browser-readable credentialed access")
			continue
		}
		if rr.Response.StatusCode < 200 || rr.Response.StatusCode >= 300 {
			r.emitDiscovery("cors", target, "cors_error_response", "CORS headers on an unsuccessful response do not prove readable application data")
			continue
		}
		if !corsSignal(rr.Response.Headers, pr.origin, pr.signal) {
			continue
		}
		// Preserve the native request. No-Origin is the negative control; a second
		// arbitrary reflected origin would itself be a positive test, not a control.
		control, err := r.probeCORS(ctx, target, "")
		if err != nil || !usableNegativeControl(baseline.Response, control.Response) ||
			corsSignal(control.Response.Headers, pr.origin, pr.signal) {
			continue
		}
		var replays []httpclient.RequestResponse
		for i := 0; i < 2; i++ {
			replay, e := r.probeCORS(ctx, target, pr.origin)
			if e != nil || replay.Response.StatusCode < 200 || replay.Response.StatusCode >= 300 || !corsSignal(replay.Response.Headers, pr.origin, pr.signal) {
				break
			}
			replays = append(replays, replay)
		}
		if len(replays) != 2 {
			continue
		}
		p := defaultPayload("cors", pr.signal, pr.origin, pr.signal)
		f := r.verifyAndBuildWithCandidate(ctx, "cors", target, p, baseline, rr, pr.signal, false, false, "", "", func(c *verification.Candidate) {
			c.RequestedProofType = verification.ProofHeaderEvidence
			c.NegativeControlSet = true
			c.NegativeControlOK = true
			c.TypedReplayHits = []bool{true, true, true}
			c.Observations = append(c.Observations, r.observation("cors", target, verification.RoleNegativeControl, 1, control))
			for i, replay := range replays {
				c.Observations = append(c.Observations, r.observation("cors", target, verification.RolePositiveReplay, i+2, replay))
			}
		})
		if f != nil {
			f.Severity = "low"
			f.Title = "CORS permits an untrusted origin"
			f.Description = fmt.Sprintf("The response repeatedly allows origin %q. Cross-origin policy exposure is confirmed; private data access is not inferred from headers alone.", pr.origin)
			if strings.EqualFold(headerValue(rr.Response.Headers, "Access-Control-Allow-Credentials"), "true") {
				f.Severity = "medium"
				f.Title = "CORS permits an untrusted origin with credentials"
			}
			r.recordFinding(ctx, &out, f, "cors", pr.signal)
		}
	}

	// Internal-origin allowlists and PNA headers describe capabilities. A header
	// alone does not demonstrate an attacker-controlled origin or an SSRF.
	for _, origin := range []string{"http://169.254.169.254", "http://localhost", "http://127.0.0.1", "http://192.168.1.1", "https://trusted-sub." + u.Hostname()} {
		if rr, err := r.probeCORS(ctx, target, origin); err == nil && headerValue(rr.Response.Headers, "Access-Control-Allow-Origin") == origin {
			r.emitDiscovery("cors", target, "internal_origin_allowed", "CORS allows "+origin+"; attacker control and private access are unproven")
		}
	}
	if rr, err := r.probeCORSOptionsPNA(ctx, target, "https://evil.example"); err == nil && pnaAllowed(rr.Response.Headers) {
		r.emitDiscovery("cors", target, "private_network_access", "PNA permission header observed; private network data access is unproven")
	}
	if r.cfg.EnableOAST && r.oast != nil && r.endpointModuleOnce("cors_oast", target) {
		if oastURL := strings.TrimSpace(r.oastURL(ctx, "cors-ssrf", target, "cors")); oastURL != "" {
			r.sendOASTProbe(ctx, target, oastURL)
			_, _ = r.probeCORS(ctx, target, oastURL)
			_, _ = r.probeCORSOptions(ctx, target, oastURL)
			_, _ = r.probeCORSServerSideSSRF(ctx, target, oastURL)
		}
	}
	return out
}

func hasCORSHeaders(headers map[string]string) bool {
	for k, v := range headers {
		lower := strings.ToLower(k)
		if strings.HasPrefix(lower, "access-control-") && strings.TrimSpace(v) != "" {
			return true
		}
		if lower == "vary" && strings.Contains(strings.ToLower(v), "origin") {
			return true
		}
	}
	return false
}

func isStaticAssetURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	clean := strings.ToLower(u.Path)
	if i := strings.IndexAny(clean, "?#"); i >= 0 {
		clean = clean[:i]
	}
	for _, ext := range []string{
		".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
		".bmp", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".webm", ".mp3",
		".wav", ".pdf", ".avif", ".map",
	} {
		if strings.HasSuffix(clean, ext) {
			return true
		}
	}
	return false
}

// probeCORS preserves the discovered request instead of rewriting an arbitrary
// parameter to an empty query value. This is important for POST/JSON endpoints
// whose CORS policy is only applied after normal request routing succeeds.
func (r *Runner) probeCORS(ctx context.Context, target ScanTarget, origin string) (httpclient.RequestResponse, error) {
	method := strings.ToUpper(strings.TrimSpace(target.Method))
	if method == "" {
		method = http.MethodGet
	}
	rawURL := target.EndpointURL
	body := []byte(target.BodyTemplate)
	headers := map[string]string{}
	if target.RequestTemplate.URL != "" {
		rawURL = target.RequestTemplate.URL
	}
	if target.RequestTemplate.Method != "" {
		method = strings.ToUpper(target.RequestTemplate.Method)
	}
	if target.RequestTemplate.Body != "" {
		body = []byte(target.RequestTemplate.Body)
	}
	for key, value := range target.RequestTemplate.Headers {
		headers[key] = value
	}
	if target.RequestTemplate.ContentType != "" && headerValue(headers, "Content-Type") == "" {
		headers["Content-Type"] = target.RequestTemplate.ContentType
	}
	if origin != "" {
		headers["Origin"] = origin
	} else {
		for key := range headers {
			if strings.EqualFold(key, "Origin") {
				delete(headers, key)
			}
		}
	}
	headers = mergeHeaders(headers, r.wafHeadersForModule("cors", rawURL))
	headers = sanitizeProbeHeaders(method, body, headers)
	return r.client.Do(ctx, method, rawURL, body, headers)
}

func (r *Runner) probeCORSOptions(ctx context.Context, target ScanTarget, origin string) (httpclient.RequestResponse, error) {
	rawURL := target.EndpointURL
	if target.RequestTemplate.URL != "" {
		rawURL = target.RequestTemplate.URL
	}
	headers := map[string]string{
		"Origin":                         origin,
		"Access-Control-Request-Method":  "GET",
		"Access-Control-Request-Headers": "Authorization, X-Requested-With",
	}
	headers = mergeHeaders(headers, r.wafHeadersForModule("cors", rawURL))
	headers = sanitizeProbeHeaders(http.MethodOptions, nil, headers)
	return r.client.Do(ctx, http.MethodOptions, rawURL, nil, headers)
}

func (r *Runner) probeCORSOptionsPNA(ctx context.Context, target ScanTarget, origin string) (httpclient.RequestResponse, error) {
	rawURL := target.EndpointURL
	if target.RequestTemplate.URL != "" {
		rawURL = target.RequestTemplate.URL
	}
	headers := map[string]string{
		"Origin":                                 origin,
		"Access-Control-Request-Method":          "GET",
		"Access-Control-Request-Private-Network": "true",
	}
	headers = mergeHeaders(headers, r.wafHeadersForModule("cors", rawURL))
	headers = sanitizeProbeHeaders(http.MethodOptions, nil, headers)
	return r.client.Do(ctx, http.MethodOptions, rawURL, nil, headers)
}

func (r *Runner) probeCORSServerSideSSRF(ctx context.Context, target ScanTarget, oastURL string) (httpclient.RequestResponse, error) {
	method := strings.ToUpper(strings.TrimSpace(target.Method))
	if method == "" {
		method = http.MethodGet
	}
	rawURL := target.EndpointURL
	if target.RequestTemplate.URL != "" {
		rawURL = target.RequestTemplate.URL
	}
	u, err := url.Parse(oastURL)
	oastHost := oastURL
	if err == nil && u.Hostname() != "" {
		oastHost = u.Hostname()
	}
	headers := map[string]string{
		"Origin":           oastURL,
		"Referer":          oastURL + "/",
		"X-Forwarded-Host": oastHost,
		"X-Rewrite-URL":    oastURL,
	}
	headers = mergeHeaders(headers, r.wafHeadersForModule("cors", rawURL))
	headers = sanitizeProbeHeaders(method, nil, headers)
	return r.client.Do(ctx, method, rawURL, nil, headers)
}

func corsSignal(headers map[string]string, origin, signal string) bool {
	acao := headerValue(headers, "Access-Control-Allow-Origin")
	switch signal {
	case "null_origin":
		return strings.EqualFold(acao, "null")
	case "origin_reflection", "partial_origin_match", "pre_domain_match", "protocol_downgrade", "trusted_subdomain",
		"localhost_origin", "cloud_metadata_origin", "intranet_origin", "unquoted_regex_dot_bypass", "special_char_bypass":
		return acao == origin
	case "private_network_access":
		return pnaAllowed(headers)
	default:
		return acao != "" && acao != "https://benign.example"
	}
}

func pnaAllowed(headers map[string]string) bool {
	pna := headerValue(headers, "Access-Control-Allow-Private-Network")
	acao := headerValue(headers, "Access-Control-Allow-Origin")
	return strings.EqualFold(pna, "true") && acao != ""
}

func corsWildcardCredentials(headers map[string]string) bool {
	acao := headerValue(headers, "Access-Control-Allow-Origin")
	acac := headerValue(headers, "Access-Control-Allow-Credentials")
	return acao == "*" && strings.EqualFold(acac, "true")
}

func headerValue(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}
