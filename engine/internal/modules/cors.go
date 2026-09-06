package modules

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

func (r *Runner) runCORS(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("cors", target); !ok {
		r.emitSkip("cors", target, reason)
		return nil
	}
	// 1. Skip static assets (.css, .js, images, fonts) - CORS credential theft is not applicable
	if isStaticAssetURL(target.EndpointURL) {
		return nil
	}

	var out []ModuleFinding
	baseline, err := r.probeCORS(ctx, target, "https://benign.example")
	if err != nil {
		return nil
	}
	targetHost := "example.com"
	if u, err := url.Parse(target.EndpointURL); err == nil && u.Hostname() != "" {
		targetHost = u.Hostname()
	}

	baseACAO := headerValue(baseline.Response.Headers, "Access-Control-Allow-Origin")
	baseACAC := headerValue(baseline.Response.Headers, "Access-Control-Allow-Credentials")
	corsActive := hasCORSHeaders(baseline.Response.Headers)

	handleProbeResult := func(pr struct{ origin, signal string }, rr httpclient.RequestResponse) {
		if hasCORSHeaders(rr.Response.Headers) {
			corsActive = true
		}
		if !corsSignal(rr.Response.Headers, pr.origin, pr.signal) {
			return
		}
		p := defaultPayload("cors", pr.signal, pr.origin, pr.signal)
		f := r.verifyAndBuild(ctx, "cors", target, p, baseline, rr, pr.signal, false, false, "", "")
		if f != nil {
			acac := headerValue(rr.Response.Headers, "Access-Control-Allow-Credentials")
			acao := headerValue(rr.Response.Headers, "Access-Control-Allow-Origin")
			hasCreds := strings.EqualFold(acac, "true")

			// Populate ResponseMarkers for yellow highlight in HTML report
			if acao != "" {
				f.Evidence.ResponseMarkers = append(f.Evidence.ResponseMarkers, acao, "Access-Control-Allow-Origin: "+acao)
			}
			if hasCreds {
				f.Evidence.ResponseMarkers = append(f.Evidence.ResponseMarkers, "Access-Control-Allow-Credentials: "+acac)
			}

			switch pr.signal {
			case "null_origin":
				if hasCreds {
					f.Severity = "high"
					f.Title = "CORS Null Origin Allowed with Credentials"
					f.Description = "The server allowed 'null' origin with Access-Control-Allow-Credentials: true. An attacker can exploit sandboxed iframes (<iframe sandbox=\"allow-scripts allow-forms\">) or local file schemes to steal authenticated victim data."
				} else {
					f.Severity = "medium"
					f.Title = "CORS Null Origin Allowed"
					f.Description = "The server reflected or allowed 'Origin: null' in Access-Control-Allow-Origin. Sandboxed iframes, local file schemes, and data: URIs generate null origin requests."
				}
			case "cloud_metadata_origin":
				if hasCreds {
					f.Severity = "critical"
					f.Title = "CORS Cloud Metadata Origin Allowed with Credentials"
					f.Description = fmt.Sprintf("Insecure CORS configuration reflected origin '%s' with Access-Control-Allow-Credentials: true. An attacker can leverage this configuration to conduct client-side pivot and steal cloud metadata tokens.", pr.origin)
				} else {
					f.Severity = "low"
					f.Title = "CORS Cloud Metadata Origin Reflected"
					f.Description = fmt.Sprintf("Insecure CORS configuration reflected origin '%s' without credentials (Access-Control-Allow-Origin: %s).", pr.origin, pr.origin)
				}
			case "localhost_origin", "intranet_origin":
				if hasCreds {
					f.Severity = "high"
				} else {
					f.Severity = "medium"
				}
				f.Title = fmt.Sprintf("CORS Intranet/Localhost Origin Allowed (%s)", pr.origin)
				f.Description = fmt.Sprintf("Insecure CORS configuration allowed internal network origin '%s' (Access-Control-Allow-Origin: %s). An attacker can exploit this to pivot through victim browsers into internal network services (Client-Side SSRF).", pr.origin, pr.origin)
				if hasCreds {
					f.Description += " Access-Control-Allow-Credentials is also set to true."
				}
			default:
				if hasCreds {
					f.Severity = "high"
					f.Title = "CORS Misconfiguration with Credentials (" + pr.signal + ")"
					f.Description = fmt.Sprintf("Insecure CORS configuration reflected origin '%s' with Access-Control-Allow-Credentials: true. An attacker can steal sensitive user data across origins.", pr.origin)
				} else {
					f.Severity = "low"
					f.Title = "CORS Permissive Origin Allowed (" + pr.signal + ")"
					f.Description = fmt.Sprintf("Insecure CORS configuration reflected arbitrary origin '%s' (Access-Control-Allow-Origin: %s). While credentials are not allowed, this allows unauthenticated cross-origin data reads.", pr.origin, pr.origin)
				}
			}
		}
		r.recordFinding(ctx, &out, f, "cors", pr.signal)
	}

	// Case 1: Arbitrary Origin Reflected directly in baseline probe!
	if baseACAO == "https://benign.example" {
		handleProbeResult(struct{ origin, signal string }{"https://benign.example", "origin_reflection"}, baseline)
		if nullRR, err := r.probeCORS(ctx, target, "null"); err == nil {
			handleProbeResult(struct{ origin, signal string }{"null", "null_origin"}, nullRR)
		}
		return out
	}

	// Case 2: Wildcard origin in baseline
	if baseACAO == "*" {
		if strings.EqualFold(baseACAC, "true") {
			p := defaultPayload("cors", "wildcard_credentials", "*", "wildcard_credentials")
			f := r.verifyAndBuild(ctx, "cors", target, p, baseline, baseline, "wildcard_credentials", false, false, "", "")
			if f != nil {
				f.Severity = "high"
				f.Title = "CORS Wildcard with Credentials"
			}
			r.recordFinding(ctx, &out, f, "cors", "wildcard_credentials")
		}
		if nullRR, err := r.probeCORS(ctx, target, "null"); err == nil {
			handleProbeResult(struct{ origin, signal string }{"null", "null_origin"}, nullRR)
		}
		return out
	}

	// Core probes: covers all distinct CORS vulnerability classes
	coreProbes := []struct {
		origin, signal string
	}{
		{"null", "null_origin"},
		{"https://evil.example", "origin_reflection"},
		{"http://169.254.169.254", "cloud_metadata_origin"},
		{"http://localhost", "localhost_origin"},
		{"https://" + targetHost + ".evil.example", "partial_origin_match"},
		{"https://trusted-sub." + targetHost, "trusted_subdomain"},
	}

	for _, pr := range coreProbes {
		if ctx.Err() != nil {
			break
		}
		rr, err := r.probeCORS(ctx, target, pr.origin)
		if err != nil {
			continue
		}
		handleProbeResult(pr, rr)
	}

	// If neither baseline nor any core probe produced any CORS header,
	// the endpoint completely ignores Origin and does not have CORS enabled.
	if !corsActive {
		return out
	}

	// Secondary bypass probes (only run if CORS is confirmed active on this endpoint)
	secondaryProbes := []struct {
		origin, signal string
	}{
		{"http://evil.example", "origin_reflection"},
		{"http://127.0.0.1", "localhost_origin"},
		{"http://192.168.1.1", "intranet_origin"},
		{"https://evil" + targetHost, "pre_domain_match"},
		{"http://" + targetHost, "protocol_downgrade"},
		{"https://" + strings.Replace(targetHost, ".", "x", 1), "unquoted_regex_dot_bypass"},
		{"https://" + targetHost + "_.evil.example", "special_char_bypass"},
		{"https://" + targetHost + ":8080", "port_bypass"},
	}

	for _, pr := range secondaryProbes {
		if ctx.Err() != nil {
			break
		}
		rr, err := r.probeCORS(ctx, target, pr.origin)
		if err != nil {
			continue
		}
		handleProbeResult(pr, rr)
	}

	// withCredentials + wildcard check
	if rr, err := r.probeCORS(ctx, target, "https://evil.example"); err == nil && corsWildcardCredentials(rr.Response.Headers) {
		p := defaultPayload("cors", "wildcard_credentials", "*", "wildcard_credentials")
		f := r.verifyAndBuild(ctx, "cors", target, p, baseline, rr, "wildcard_credentials", false, false, "", "")
		if f != nil {
			f.Severity = "high"
			f.Title = "CORS Wildcard with Credentials"
		}
		r.recordFinding(ctx, &out, f, "cors", "wildcard_credentials")
	}

	// W3C Private Network Access (PNA) Preflight Probe
	if pnaRR, pnaErr := r.probeCORSOptionsPNA(ctx, target, "https://evil.example"); pnaErr == nil && pnaAllowed(pnaRR.Response.Headers) {
		p := defaultPayload("cors", "pna_allowed", "https://evil.example", "private_network_access")
		f := r.verifyAndBuild(ctx, "cors", target, p, baseline, pnaRR, "private_network_access", false, false, "", "")
		if f != nil {
			f.Severity = "high"
			f.Title = "CORS Private Network Access (PNA) Allowed"
			f.Description = "The endpoint responded with Access-Control-Allow-Private-Network: true to a public origin. This allows public websites to bypass browser PNA restrictions and send cross-origin requests to private/internal network resources."
		}
		r.recordFinding(ctx, &out, f, "cors", "private_network_access")
	}

	// Server-Side Origin Validation SSRF Probe via OAST (run once per host/origin, only if CORS is active)
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
	headers["Origin"] = origin
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
		"localhost_origin", "cloud_metadata_origin", "intranet_origin":
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
