package modules

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/verification"
)

var criticalSecurityHeaders = []struct {
	name, signal string
}{
	{"Content-Security-Policy", "missing_csp"},
	{"X-Frame-Options", "missing_xfo"},
	{"X-Content-Type-Options", "missing_xcto"},
	{"Strict-Transport-Security", "missing_hsts"},
	{"Referrer-Policy", "missing_referrer_policy"},
	{"Permissions-Policy", "missing_permissions_policy"},
	{"Cross-Origin-Opener-Policy", "missing_coop"},
}

func (r *Runner) runSecurityHeaders(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("security_headers", target); !ok {
		r.emitSkip("security_headers", target, reason)
		return nil
	}
	if !r.endpointModuleOnce("security_headers", target) {
		return nil
	}
	if orig, ok := originScanTarget(target); ok {
		target = orig
	}
	rr, err := r.cachedEmptyProbe(ctx, target)
	if err != nil {
		return nil
	}
	baseline := httpclient.RequestResponse{
		Response: httpclient.ResponseRecord{StatusCode: 200, Body: "", Headers: map[string]string{}},
	}
	var out []ModuleFinding
	missing := 0
	for _, h := range criticalSecurityHeaders {
		if headerValue(rr.Response.Headers, h.name) != "" {
			continue
		}
		missing++
	}
	// A single omitted defence-in-depth header is noisy.  Keep the existing
	// threshold for missing-header reports, but do not let it suppress a
	// positively observed unsafe CSP below.
	if missing >= 2 {
		for _, h := range criticalSecurityHeaders {
			if headerValue(rr.Response.Headers, h.name) != "" {
				continue
			}
			p := defaultPayload("security_headers", h.signal, h.name, h.signal)
			f := r.verifyAndBuild(ctx, "security_headers", target, p, baseline, rr, h.signal, false, false, "", "")
			r.recordFinding(ctx, &out, f, "security_headers", h.signal)
		}
	}
	if v := headerValue(rr.Response.Headers, "X-Frame-Options"); strings.EqualFold(v, "ALLOWALL") {
		p := defaultPayload("security_headers", "weak_xfo", v, "weak_xfo")
		f := r.verifyAndBuild(ctx, "security_headers", target, p, baseline, rr, "weak_xfo", false, false, "", "")
		r.recordFinding(ctx, &out, f, "security_headers", "weak_xfo")
	}
	for _, weakness := range weakCSPDirectives(headerValue(rr.Response.Headers, "Content-Security-Policy")) {
		p := defaultPayload("security_headers", weakness.signal, weakness.value, weakness.signal)
		f := r.verifyAndBuild(ctx, "security_headers", target, p, baseline, rr, weakness.signal, false, false, "", "")
		r.recordFinding(ctx, &out, f, "security_headers", weakness.signal)
	}
	if value := strings.TrimSpace(headerValue(rr.Response.Headers, "Cross-Origin-Opener-Policy")); value != "" && !validCOOP(value) {
		p := defaultPayload("security_headers", "weak_coop", value, "weak_coop")
		f := r.verifyAndBuild(ctx, "security_headers", target, p, baseline, rr, "weak_coop", false, false, "", "")
		r.recordFinding(ctx, &out, f, "security_headers", "weak_coop")
	}
	for _, name := range []string{"X-ChromeLogger-Data", "X-ChromePhp-Data"} {
		if value := headerValue(rr.Response.Headers, name); chromeLoggerDisclosure(value) {
			p := defaultPayload("security_headers", "chrome_logger_disclosure", name, "chrome_logger_disclosure")
			f := r.verifyAndBuild(ctx, "security_headers", target, p, baseline, rr, "chrome_logger_disclosure", false, false, "", "")
			if f != nil {
				f.Severity = "medium"
				f.Title = "Chrome Logger Debug Data Disclosed"
				f.Description = name + " exposes structured server-side debug data to unauthenticated clients."
				r.recordFinding(ctx, &out, f, "security_headers", "chrome_logger_disclosure")
			}
			break
		}
	}
	return out
}

func validCOOP(value string) bool {
	value = strings.ToLower(strings.TrimSpace(strings.Split(value, ";")[0]))
	return value == "same-origin" || value == "same-origin-allow-popups" || value == "noopener-allow-popups"
}

// Chrome Logger values are base64-encoded JSON. Requiring both layers avoids
// flagging unrelated proprietary headers that merely reuse the same name.
func chromeLoggerDisclosure(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 1<<20 {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(value)
	}
	if err != nil || len(raw) < 2 {
		return false
	}
	var decoded interface{}
	if json.Unmarshal(raw, &decoded) != nil {
		return false
	}
	switch typed := decoded.(type) {
	case map[string]interface{}:
		return len(typed) > 0
	case []interface{}:
		return len(typed) > 0
	default:
		return false
	}
}

type cspWeakness struct {
	signal string
	value  string
}

// weakCSPDirectives deliberately reports only source expressions that permit
// script execution.  It does not turn every missing best-practice directive
// into a finding, which keeps the passive/configuration signal actionable.
func weakCSPDirectives(policy string) []cspWeakness {
	directives := parseCSP(policy)
	scriptSources := directives["script-src"]
	if len(scriptSources) == 0 {
		scriptSources = directives["default-src"]
	}
	if len(scriptSources) == 0 {
		return nil
	}

	var out []cspWeakness
	hasNonceOrHash := false
	for _, source := range scriptSources {
		lower := strings.ToLower(source)
		if strings.HasPrefix(lower, "'nonce-") || strings.HasPrefix(lower, "'sha256-") ||
			strings.HasPrefix(lower, "'sha384-") || strings.HasPrefix(lower, "'sha512-") {
			hasNonceOrHash = true
		}
	}
	for _, source := range scriptSources {
		switch strings.ToLower(source) {
		case "'unsafe-inline'":
			// CSP3 ignores unsafe-inline when a nonce/hash is present.  Treating
			// that compatibility token as exploitable creates a common false
			// positive, so only report it when it is actually effective.
			if !hasNonceOrHash {
				out = append(out, cspWeakness{signal: "csp_unsafe_inline_script", value: source})
			}
		case "'unsafe-eval'", "wasm-unsafe-eval":
			out = append(out, cspWeakness{signal: "csp_unsafe_eval_script", value: source})
		case "*":
			out = append(out, cspWeakness{signal: "csp_wildcard_script_source", value: source})
		}
	}
	return out
}

func parseCSP(policy string) map[string][]string {
	directives := make(map[string][]string)
	for _, rawDirective := range strings.Split(policy, ";") {
		fields := strings.Fields(rawDirective)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		if _, exists := directives[name]; !exists {
			directives[name] = append([]string(nil), fields[1:]...)
		}
	}
	return directives
}

func (r *Runner) runTLSMisconfig(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("tls_misconfig", target); !ok {
		r.emitSkip("tls_misconfig", target, reason)
		return nil
	}
	u, err := url.Parse(target.EndpointURL)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || r.tlsInspector == nil {
		return nil
	}
	hostKey := strings.ToLower(u.Host)
	r.tlsMu.Lock()
	if _, reported := r.tlsReported[hostKey]; reported {
		r.tlsMu.Unlock()
		return nil
	}
	r.tlsReported[hostKey] = struct{}{}
	r.tlsMu.Unlock()
	inspection, err := r.tlsInspector.Inspect(ctx, target.EndpointURL)
	if err != nil {
		r.emitOnce("tls-inspect:"+u.Host, "module_notice", "TLS inspection could not be completed", map[string]interface{}{
			"module": "tls_misconfig", "endpoint": target.EndpointURL, "error": err.Error(),
		})
		return nil
	}
	rr := httpclient.RequestResponse{
		Request: httpclient.RequestRecord{Method: http.MethodGet, URL: target.EndpointURL},
		Response: httpclient.ResponseRecord{StatusCode: http.StatusOK, Headers: map[string]string{
			"TLS-Protocol": inspection.Protocol, "TLS-Cipher": inspection.Cipher,
			"TLS-Certificate-Subject": inspection.CertificateSubject,
			"TLS-Certificate-Issuer":  inspection.CertificateIssuer,
			"TLS-Certificate-Expiry":  inspection.CertificateExpiry.Format("2006-01-02T15:04:05Z07:00"),
		}},
	}
	var out []ModuleFinding
	for _, signal := range inspection.Signals {
		p := defaultPayload("tls_misconfig", signal, signal, signal)
		severity := "low"
		if signal == "expired_certificate" || signal == "hostname_mismatch" || signal == "self_signed_certificate" || signal == "certificate_not_yet_valid" || signal == "untrusted_certificate_chain" {
			severity = "medium"
		}
		observation := r.observation("tls_misconfig", target, verification.RolePositiveProbe, 1, rr)
		f := &ModuleFinding{
			Title: "TLS configuration: " + strings.ReplaceAll(signal, "_", " "), VulnClass: "tls_misconfig", Severity: severity,
			Description: fmt.Sprintf("TLS inspection confirmed %s (protocol=%s, cipher=%s, subject=%s, issuer=%s, expires=%s)",
				signal, inspection.Protocol, inspection.Cipher, inspection.CertificateSubject,
				inspection.CertificateIssuer, inspection.CertificateExpiry.Format("2006-01-02")),
			Endpoint: target.EndpointURL, Confidence: verification.Confirmed,
			Evidence: Evidence{
				Module: "tls_misconfig", Signal: signal, Payload: p, Request: rr.Request, Response: rr.Response,
				Verification: verification.Result{
					Confidence: verification.Confirmed, Score: 1, StabilityRatio: 1,
					ProofType:      verification.ProofConfiguration,
					ProofPolicy:    verification.CurrentProofPolicyVersion,
					ProofSatisfied: true, Observations: []verification.Observation{observation},
					UpgradeReasons: []string{"direct_tls_handshake"}, VerifiedAt: time.Now().UTC(),
				},
				DetectedAt: time.Now().UTC(),
			},
		}
		r.recordFinding(ctx, &out, f, "tls_misconfig", signal)
	}
	return out
}
