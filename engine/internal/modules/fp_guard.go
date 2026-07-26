package modules

import (
	"strings"

	"github.com/akha-security/akca/engine/internal/deeptraversal"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/nosql"
	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/sensitivedata"
	"github.com/akha-security/akca/engine/internal/verification"
)

type fpCategory string

const (
	fpDifferential   fpCategory = "differential"
	fpContentMatch   fpCategory = "content_match"
	fpInformational  fpCategory = "informational"
	fpHeaderEvidence fpCategory = "header_evidence"
)

func fpCategoryFor(module string) fpCategory {
	switch module {
	case "security_headers", "tls_misconfig", "rate_limit", "api_exposure", "api_versioning":
		return fpInformational
	case "secret_exposure", "sensitive_data", "cicd_exposure", "git_recovery",
		"source_code_disclosure", "cloud_storage", "cloud_posture", "vulnerable_components":
		return fpContentMatch
	case "cors", "open_redirect", "host_header", "crlf", "cache_poisoning", "cache_deception", "jwt", "oauth":
		return fpHeaderEvidence
	default:
		return fpDifferential
	}
}

func moduleSignalConfirmed(
	module string,
	p payloadgen.Payload,
	signal string,
	baseline, probe httpclient.ResponseRecord,
	domExecuted bool,
	oastURL string,
) bool {
	if signal == "" {
		return false
	}
	if probe.StatusCode == 0 {
		return false
	}
	body, baseBody := probe.Body, baseline.Body
	baseHeaders, probeHeaders := baseline.Headers, probe.Headers
	probeStatus, baseStatus := probe.StatusCode, baseline.StatusCode

	switch module {
	case "sqli":
		if signal == "oob_sqli" {
			return false
		}
		if signal == "delayed_timing_confirmed" {
			return true
		}
		if signal == "boolean_differential" || signal == "boolean_length" {
			if clientErrorStatus(probeStatus) && probeStatus != baseStatus {
				return false
			}
		}
		return sqliSignalConfirmed(p, body, baseBody, signal)
	case "xss":
		if signal == "dom_execution" && domExecuted {
			return !sqliErrorRe.MatchString(body)
		}
		return xssSignalConfirmed(p, body, baseBody, signal)
	case "ssti":
		return sstiSignalConfirmed(p, body, baseBody, signal)
	case "command_injection":
		if signal == "delayed_timing_confirmed" {
			return true
		}
		return cmdInjSignalConfirmed(p, body, baseBody, signal)
	case "nosql":
		return nosqlSignalConfirmed(body, baseBody, probeStatus, baseStatus, signal)
	case "ssrf":
		if signal == "blind_oast" {
			return false
		}
		return ssrfSignalConfirmed(p, baseline, probe, signal)
	case "xxe":
		if signal == "blind_oast" {
			return false
		}
		return xxeSignalConfirmed(body, baseBody, signal)
	case "lfi":
		if signal == "rfi_oast" {
			return false
		}
		return deeptraversal.DetectSignal(body, baseBody, signal)
	case "blind_xss":
		return false
	case "open_redirect":
		return openRedirectHeaderConfirmed(probeHeaders, signal)
	case "host_header":
		return hostHeaderSignal(body, baseBody)
	case "cors":
		return corsSignalConfirmed(baseHeaders, probeHeaders, signal, p.Value)
	case "secret_exposure":
		return secretExposureConfirmed(body, baseBody, signal)
	case "sensitive_data":
		if body == baseBody {
			return false
		}
		return len(sensitivedata.Analyze(body)) > len(sensitivedata.Analyze(baseBody))
	case "cicd_exposure":
		return cicdExposureSignal(p.Value, body)
	case "rate_limit":
		if signal == "policy_violation_confirmed" {
			return probeStatus > 0 && !rateLimitBlockSignal(probeStatus, body)
		}
		return probeStatus >= 200 && probeStatus < 400
	case "security_headers", "tls_misconfig", "api_exposure", "api_versioning":
		return probeStatus >= 200 && probeStatus < 400
	case "jwt":
		return jwtModuleConfirmed(body, baseBody, signal, probeStatus, baseStatus)
	case "oauth":
		if signal == "redirect_uri_location_confirmed" {
			return oauthProofSignal(p, baseline, probe)
		}
		return oauthModuleConfirmed(body, baseBody, signal, probeStatus, baseStatus)
	case "cache_poisoning":
		return cachePoisonPersisted(baseBody, body, probeHeaders, p.Value)
	case "cache_deception":
		return signal == "private_canary_anonymous_cache_hit" &&
			probeStatus == 200 && cacheEvidence(probeHeaders)
	case "broken_auth":
		return brokenAuthSignal(probe, baseline)
	case "bfla":
		return signal == "protected_state_mutation" &&
			probeStatus >= 200 && probeStatus < 300 &&
			resourceFingerprint(body) != resourceFingerprint(baseBody)
	case "client_ssti":
		if domExecuted && signal == "angular_dom_execution" {
			return true
		}
		return clientSSTIModuleConfirmed(body, baseBody, p.Value, signal, probeStatus, baseStatus)
	case "smuggling":
		return smugglingModuleConfirmed(probeHeaders, body, baseBody, probeStatus, baseStatus)
	case "ldap_xpath_injection":
		return ldapXPathModuleConfirmed(body, baseBody, p.Value, signal, probeStatus, baseStatus)
	case "crlf":
		return crlfHeaderConfirmed(baseHeaders, probeHeaders, p.Value)
	case "debug_admin":
		return debugAdminSignal(body, probeStatus)
	case "race_condition":
		return signal == "multiple_unique_side_effects" &&
			probeStatus >= 200 && probeStatus < 300 &&
			resourceFingerprint(body) != resourceFingerprint(baseBody)
	case "business_logic":
		return signal == "forbidden_state_persisted" &&
			probeStatus >= 200 && probeStatus < 300 &&
			resourceFingerprint(body) != resourceFingerprint(baseBody)
	case "hpp":
		return signal == "forbidden_state_persisted" &&
			probeStatus >= 200 && probeStatus < 300 &&
			resourceFingerprint(body) != resourceFingerprint(baseBody)
	case "file_upload":
		return signal == "retrieved_hash_confirmed" && probeStatus == 200 &&
			len(strings.TrimSpace(body)) > 0
	case "second_order":
		if p.Value != "" && strings.Contains(body, p.Value) && !strings.Contains(baseBody, p.Value) {
			return true
		}
		return differentialWithStatusGuard(body, baseBody, p.Value, probeStatus, baseStatus)
	case "git_recovery":
		return probeStatus == 200 && body != baseBody && len(strings.TrimSpace(body)) > 4 &&
			(isGitContent(body) || strings.Contains(body, "Exposed .git") || strings.Contains(body, "partial_git_exposure"))
	case "mass_assignment":
		return (signal == "role_escalation" || signal == "hidden_admin_flag" || signal == "permission_injection") &&
			probeStatus >= 200 && probeStatus < 300 &&
			resourceFingerprint(body) != resourceFingerprint(baseBody)
	case "idor":
		return signal == "foreign_object_access" &&
			probeStatus >= 200 && probeStatus < 300 &&
			(baseStatus == 401 || baseStatus == 403 || !successfulResourceResponse(baseline)) &&
			successfulResourceResponse(probe)
	case "csrf", "account_enum",
		"prototype_pollution",
		"wordpress_fuzz", "graphql", "websocket",
		"cloud_posture",
		"source_code_disclosure", "script_source",
		"vulnerable_components", "cloud_storage":
		return differentialWithStatusGuard(body, baseBody, p.Value, probeStatus, baseStatus)
	default:
		if isPendingOASTSignal(signal, oastURL) {
			return false
		}
		return differentialWithStatusGuard(body, baseBody, p.Value, probeStatus, baseStatus)
	}
}

func differentialBodyConfirmed(body, baseline, payload string) bool {
	normBody := normalizeVolatileFields(body)
	normBase := normalizeVolatileFields(baseline)
	if normBody == normBase {
		return false
	}
	if injectionPayloadReflected(payload, body, baseline) {
		return bodyDiffRatio(normBase, normBody) >= 0.15
	}
	return bodyDiffRatio(normBase, normBody) >= 0.12
}

func nosqlSignalConfirmed(body, baseline string, probeStatus, baseStatus int, signal string) bool {
	if body == baseline && probeStatus == baseStatus {
		return false
	}
	if signal == "nosql_error_disclosure" {
		// MongoDB/operator exceptions commonly use HTTP 500. Accept only the
		// provider-specific marker set; generic status changes and framework
		// error pages remain insufficient.
		return nosql.IsMongoErrorDisclosure(body, baseline)
	}
	if statusOnlyDifferential(probeStatus, baseStatus) {
		return false
	}
	switch signal {
	case "nosql_auth_bypass":
		if probeStatus < 200 || probeStatus >= 300 {
			return false
		}
		lower := strings.ToLower(body)
		for _, tok := range []string{"access_token", "token", "authenticated", "success", "session"} {
			if strings.Contains(lower, tok) && !strings.Contains(strings.ToLower(baseline), tok) {
				return true
			}
		}
		return false
	default:
		return bodyDiffRatio(baseline, body) >= 0.06
	}
}

func ssrfSignalConfirmed(p payloadgen.Payload, baseline, probe httpclient.ResponseRecord, signal string) bool {
	if payloadReflectedAnyEncoding(p.Value, probe.Body, baseline.Body) {
		return false
	}
	body := strings.ToLower(probe.Body)
	base := strings.ToLower(baseline.Body)
	if body == base || strings.TrimSpace(body) == "" {
		return false
	}
	if signal == "" || signal == "cloud_metadata" {
		switch {
		case strings.Contains(strings.ToLower(p.Value), "metadata.google"):
			signal = "gcp_metadata"
		case strings.Contains(strings.ToLower(p.Value), "metadata/instance"):
			signal = "azure_metadata"
		case strings.Contains(strings.ToLower(p.Value), "169.254.169.254"),
			strings.Contains(strings.ToLower(p.Value), "2852039166"):
			signal = "aws_metadata"
		}
	}
	switch signal {
	case "aws_metadata":
		return newMarkerCount(body, base, []string{
			"ami-id", "instance-id", "instance-type", "local-hostname",
			"iam/security-credentials", "security-credentials/",
		}) >= 2
	case "gcp_metadata":
		if !strings.EqualFold(headerCI(probe.Headers, "Metadata-Flavor"), "Google") {
			return false
		}
		return newMarkerCount(body, base, []string{
			"project/project-id", "instance/id", "service-accounts/", "hostname",
		}) >= 1
	case "azure_metadata":
		return newMarkerCount(body, base, []string{`"compute"`, `"vmid"`, `"subscriptionid"`}) == 3
	case "internal_ip", "protocol_smuggling":
		// A private address, scheme, or validation message is not proof that
		// the server fetched anything. These paths require OAST/canary evidence.
		return false
	default:
		return false
	}
}

func newMarkerCount(body, baseline string, markers []string) int {
	count := 0
	for _, marker := range markers {
		if strings.Contains(body, marker) && !strings.Contains(baseline, marker) {
			count++
		}
	}
	return count
}

func xxeSignalConfirmed(body, baseline, signal string) bool {
	switch signal {
	case "classic_entity":
		return strings.Contains(body, "AKCA_XXE_TEST") && !strings.Contains(baseline, "AKCA_XXE_TEST")
	case "soap_xxe":
		return strings.Contains(strings.ToLower(body), "soap") &&
			strings.Contains(body, "AKCA_XXE_TEST") && !strings.Contains(baseline, "AKCA_XXE_TEST")
	default:
		return false
	}
}

func openRedirectHeaderConfirmed(headers map[string]string, signal string) bool {
	loc := headerCI(headers, "Location")
	if loc == "" {
		return false
	}
	low := strings.ToLower(loc)
	if strings.Contains(low, "evil.example") {
		return true
	}
	return signal == "javascript_uri" && strings.HasPrefix(low, "javascript:")
}

func corsSignalConfirmed(baseHeaders, probeHeaders map[string]string, signal, origin string) bool {
	acao := headerCI(probeHeaders, "Access-Control-Allow-Origin")
	if acao == "" {
		return false
	}
	baseAcao := headerCI(baseHeaders, "Access-Control-Allow-Origin")
	if acao == baseAcao && signal != "wildcard_credentials" {
		return false
	}
	switch signal {
	case "null_origin":
		return strings.EqualFold(acao, "null") &&
			strings.EqualFold(headerCI(probeHeaders, "Access-Control-Allow-Credentials"), "true")
	case "origin_reflection":
		return acao == origin &&
			strings.EqualFold(headerCI(probeHeaders, "Access-Control-Allow-Credentials"), "true")
	case "partial_origin_match":
		return acao == origin && !strings.Contains(baseAcao, "evil.example") &&
			strings.EqualFold(headerCI(probeHeaders, "Access-Control-Allow-Credentials"), "true")
	case "wildcard_credentials":
		// Browsers reject credentialed reads when ACAO is "*"; this header
		// combination alone is therefore not evidence of exploitable CORS.
		return false
	default:
		return false
	}
}

func headerCI(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func clientErrorStatus(code int) bool {
	switch code {
	case 400, 403, 404, 405, 415, 422, 429:
		return true
	default:
		return false
	}
}

// isCDNErrorStatus returns true for Cloudflare-specific status codes (520-527)
// and other reverse-proxy / CDN infrastructure errors that indicate network-layer
// problems — NOT application-level SQL errors or vulnerability evidence.
//
//	520 = Web server returned an unknown error
//	521 = Web server is down
//	522 = Connection timed out
//	523 = Origin is unreachable
//	524 = A timeout occurred
//	525 = SSL handshake failed
//	526 = Invalid SSL certificate
//	527 = Railgun error
func isCDNErrorStatus(code int) bool {
	return code >= 520 && code <= 530
}

// isInfrastructureError returns true for status codes that indicate
// infrastructure / reverse-proxy failures rather than application behavior.
// These should not be treated as evidence of injection vulnerabilities.
func isInfrastructureError(code int) bool {
	if isCDNErrorStatus(code) {
		return true
	}
	// 500/501 can carry genuine SQL/application error messages, so we only
	// treat 502+ as infrastructure noise (proxy/gateway/timeout errors).
	return code >= 502 && code <= 599
}

func shouldSuppressLowConfidence(module string, signal string, score float64, conf string) bool {
	_ = conf
	cat := fpCategoryFor(module)
	switch cat {
	case fpInformational:
		return score < 0.45
	case fpContentMatch:
		return score < 0.55
	case fpHeaderEvidence:
		return score < 0.45
	default:
		if strings.Contains(strings.ToLower(signal), "timing") || strings.Contains(strings.ToLower(signal), "oast") {
			return score < 0.85
		}
		switch module {
		case "xss", "sqli", "ssti", "xxe", "command_injection":
			return score < 0.80
		default:
			return score < 0.60
		}
	}
}

func isGitContent(body string) bool {
	return strings.HasPrefix(body, "ref:") ||
		strings.Contains(body, "PACK") ||
		strings.Contains(body, "HEAD\x00") ||
		strings.Contains(body, "[core]")
}

func normalizeVolatileFields(body string) string {
	return verification.NormalizeVolatileFields(body)
}
