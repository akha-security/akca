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
	var out []ModuleFinding
	baseline, err := r.probeCORS(ctx, target, "https://benign.example")
	if err != nil {
		return nil
	}
	targetHost := "example.com"
	if u, err := url.Parse(target.EndpointURL); err == nil && u.Hostname() != "" {
		targetHost = u.Hostname()
	}

	probes := []struct {
		origin, signal string
	}{
		{"null", "null_origin"},
		{"https://evil.example", "origin_reflection"},
		{"http://evil.example", "origin_reflection"},
		// Intranet & Cloud Metadata Origins (Client-Side SSRF / Intranet Pivoting via CORS)
		{"http://127.0.0.1", "localhost_origin"},
		{"http://localhost", "localhost_origin"},
		{"http://169.254.169.254", "cloud_metadata_origin"},
		{"http://192.168.1.1", "intranet_origin"},
		{"http://10.0.0.1", "intranet_origin"},
		{"http://172.16.0.1", "intranet_origin"},
		{"http://[::1]", "localhost_origin"},
		{"http://0.0.0.0", "localhost_origin"},
	}

	// Advanced domain regex bypasses (prefix, suffix, unquoted dot, subdomains, ports, special chars)
	probes = append(probes,
		struct{ origin, signal string }{"https://" + targetHost + ".evil.example", "partial_origin_match"},
		struct{ origin, signal string }{"https://evil" + targetHost, "pre_domain_match"},
		struct{ origin, signal string }{"http://" + targetHost, "protocol_downgrade"},
		struct{ origin, signal string }{"https://trusted-sub." + targetHost, "trusted_subdomain"},
		struct{ origin, signal string }{"https://" + strings.Replace(targetHost, ".", "x", 1), "unquoted_regex_dot_bypass"},
		struct{ origin, signal string }{"https://" + targetHost + "_.evil.example", "special_char_bypass"},
		struct{ origin, signal string }{"https://" + targetHost + ":8080", "port_bypass"},
	)
	for _, pr := range probes {
		rr, err := r.probeCORS(ctx, target, pr.origin)
		if err != nil {
			continue
		}
		if !corsSignal(rr.Response.Headers, pr.origin, pr.signal) {
			continue
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
				f.Severity = "critical"
				f.Title = "CORS Cloud Metadata Origin Allowed (Client-Side SSRF Pivot)"
				f.Description = fmt.Sprintf("Insecure CORS configuration reflected/allowed Cloud Metadata origin '%s' (Access-Control-Allow-Origin: %s). An attacker can leverage a victim's browser to pivot and exfiltrate cloud instance metadata.", pr.origin, pr.origin)
				if hasCreds {
					f.Description += " Access-Control-Allow-Credentials is also set to true."
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

	// withCredentials + wildcard
	rr, err := r.probeCORS(ctx, target, "https://evil.example")
	if err == nil && corsWildcardCredentials(rr.Response.Headers) {
		p := defaultPayload("cors", "wildcard_credentials", "*", "wildcard_credentials")
		f := r.verifyAndBuild(ctx, "cors", target, p, baseline, rr, "wildcard_credentials", false, false, "", "")
		if f != nil {
			f.Severity = "high"
			f.Title = "CORS Wildcard with Credentials"
		}
		r.recordFinding(ctx, &out, f, "cors", "wildcard_credentials")
	}

	// W3C Private Network Access (PNA) Preflight Probe
	pnaRR, pnaErr := r.probeCORSOptionsPNA(ctx, target, "https://evil.example")
	if pnaErr == nil && pnaAllowed(pnaRR.Response.Headers) {
		p := defaultPayload("cors", "pna_allowed", "https://evil.example", "private_network_access")
		f := r.verifyAndBuild(ctx, "cors", target, p, baseline, pnaRR, "private_network_access", false, false, "", "")
		if f != nil {
			f.Severity = "high"
			f.Title = "CORS Private Network Access (PNA) Allowed"
			f.Description = "The endpoint responded with Access-Control-Allow-Private-Network: true to a public origin. This allows public websites to bypass browser PNA restrictions and send cross-origin requests to private/internal network resources."
		}
		r.recordFinding(ctx, &out, f, "cors", "private_network_access")
	}

	// Server-Side Origin Validation SSRF Probe via OAST
	if r.cfg.EnableOAST && r.oast != nil {
		if oastURL := strings.TrimSpace(r.oastURL(ctx, "cors-ssrf-"+target.Parameter, target, "cors")); oastURL != "" {
			r.sendOASTProbe(ctx, target, oastURL)
			_, _ = r.probeCORS(ctx, target, oastURL)
			_, _ = r.probeCORSOptions(ctx, target, oastURL)
			_, _ = r.probeCORSServerSideSSRF(ctx, target, oastURL)
		}
	}

	return out
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
		"Origin":                                origin,
		"Access-Control-Request-Method":         "GET",
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
