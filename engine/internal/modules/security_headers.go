package modules

import (
	"context"
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
}

func (r *Runner) runSecurityHeaders(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("security_headers", target); !ok {
		r.emitSkip("security_headers", target, reason)
		return nil
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
	if missing < 2 {
		return out
	}
	for _, h := range criticalSecurityHeaders {
		if headerValue(rr.Response.Headers, h.name) != "" {
			continue
		}
		p := defaultPayload("security_headers", h.signal, h.name, h.signal)
		f := r.verifyAndBuild(ctx, "security_headers", target, p, baseline, rr, h.signal, false, false, "", "")
		r.recordFinding(&out, f, "security_headers", h.signal)
	}
	if v := headerValue(rr.Response.Headers, "X-Frame-Options"); strings.EqualFold(v, "ALLOWALL") {
		p := defaultPayload("security_headers", "weak_xfo", v, "weak_xfo")
		f := r.verifyAndBuild(ctx, "security_headers", target, p, baseline, rr, "weak_xfo", false, false, "", "")
		r.recordFinding(&out, f, "security_headers", "weak_xfo")
	}
	return out
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
		r.recordFinding(&out, f, "tls_misconfig", signal)
	}
	return out
}
