package modules

import (
	"encoding/json"
	"strings"

	"github.com/akha-security/akca/engine/internal/deeptraversal"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/nosql"
	"github.com/akha-security/akca/engine/internal/payloadgen"
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
	case "security_headers", "cookie_security", "tls_misconfig", "rate_limit", "api_exposure", "api_versioning":
		return fpInformational
	case "secret_exposure", "sensitive_data", "cicd_exposure", "git_recovery",
		"source_code_disclosure", "cloud_storage", "cloud_posture", "vulnerable_components", "llm_injection":
		return fpContentMatch
	case "actuator", "backup_archives", "cloud_takeover", "devops_exposure", "route_auth_bypass", "tenant_isolation", "account_recovery", "webhook_security", "session_lifecycle", "parser_differential",
		"nginx_alias", "nextjs_bypass", "framework_debug", "iis_discovery",
		"firebase_misconfig", "spring_cloud_jolokia", "saas_exposure", "pdf_injection",
		"cpdos", "proxy_path_confusion", "ws_cswsh", "jsonp_callback",
		"react_rsc_rce", "server_side_js_injection", "csti_detection", "swagger_exposure", "sensitive_file_discovery",
		"http_smuggling", "race_condition_sync", "oauth_flow_audit",
		"cloud_native_exposure", "grpc_scan":
		return fpContentMatch
	case "cors", "open_redirect", "host_header", "host_poisoning", "crlf", "cache_poisoning", "cache_deception", "jwt", "oauth":
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
	case "host_poisoning":
		if strings.HasSuffix(signal, "_body_reflection") {
			return strings.Contains(strings.ToLower(body), strings.ToLower(p.Value)) &&
				!strings.Contains(strings.ToLower(baseBody), strings.ToLower(p.Value))
		}
		for key, value := range probeHeaders {
			if strings.EqualFold(key, "Location") && strings.Contains(strings.ToLower(value), strings.ToLower(p.Value)) {
				return true
			}
		}
		return false
	case "cors":
		return corsSignalConfirmed(baseHeaders, probeHeaders, signal, p.Value)
	case "secret_exposure":
		return secretExposureConfirmed(body, baseBody, signal)
	case "sensitive_data":
		return sensitiveDataSignalConfirmed(body, baseBody, signal, p.Value)
	case "cicd_exposure":
		return cicdExposureSignal(p.Value, body)
	case "rate_limit":
		if signal == "policy_violation_confirmed" {
			return probeStatus > 0 && !rateLimitBlockSignal(probeStatus, body)
		}
		if signal == "rate_limit_threshold_discovered" {
			return rateLimitBlockSignal(probeStatus, body)
		}
		if signal == "missing_rate_limiting" {
			return rateLimitAttemptProcessed(probeStatus, body)
		}
		return probeStatus >= 200 && probeStatus < 400
	case "security_headers", "cookie_security", "tls_misconfig", "api_exposure", "api_versioning":
		return probeStatus >= 200 && probeStatus < 400
	case "llm_injection":
		pr := llmProbe{
			payload:     p.Value,
			signal:      signal,
			matchMarker: p.Value,
		}
		if strings.Contains(p.Value, "AKCA_SYSTEM_PROMPT_LEAK:") {
			pr.matchMarker = "AKCA_SYSTEM_PROMPT_LEAK:"
			pr.instructionEcho = "ignore previous instructions"
		} else if strings.Contains(p.Value, "AKCA_INSTRUCTION_OVERRIDE_CONFIRMED") {
			pr.matchMarker = "AKCA_INSTRUCTION_OVERRIDE_CONFIRMED"
			pr.instructionEcho = "---end of user input---"
		} else if strings.Contains(p.Value, "AKCA_PROMPT_DEBUG_MODE_CONFIRMED") {
			pr.matchMarker = "AKCA_PROMPT_DEBUG_MODE_CONFIRMED"
			pr.instructionEcho = "[inst] <<sys>>"
		}
		return isLegitimateLLMOutput(probe, baseline, pr)
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
	case "route_auth_bypass":
		return isRouteBypassSuccessful(probe, baseline)
	case "tenant_isolation":
		return signal == "cross_tenant_access_confirmed" && successfulResourceResponse(probe)
	case "account_recovery":
		return signal == "recovery_state_mutation" && probeStatus >= 200 && probeStatus < 300 &&
			resourceFingerprint(body) != resourceFingerprint(baseBody)
	case "webhook_security":
		return signal == "unauthenticated_webhook_state_mutation" && probeStatus >= 200 && probeStatus < 300 &&
			resourceFingerprint(body) != resourceFingerprint(baseBody)
	case "session_lifecycle":
		return probe.StatusCode == 200 && privateAuthResourceEvidence(probe.Body)
	case "parser_differential":
		return probe.StatusCode == 200 && probe.Body != baseline.Body && len(strings.TrimSpace(probe.Body)) > 20
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
		return crlfSignalConfirmed(baseHeaders, probeHeaders, baseBody, body, p.Value, signal)
	case "debug_admin":
		return debugAdminSignal(body, probeStatus)
	case "actuator":
		return actuatorSignalConfirmed(signal, probe)
	case "backup_archives":
		return backupArchiveSignalConfirmed(signal, probe)
	case "cloud_takeover":
		return cloudTakeoverSignalConfirmed(signal, probe)
	case "devops_exposure":
		return devopsExposureSignalConfirmed(signal, probeStatus, body)
	case "http_methods":
		return (signal == "http_put_unauthenticated_upload" && probeStatus == 200 && strings.Contains(body, p.Value)) ||
			(signal == "http_trace_xst" && probeStatus == 200 && strings.Contains(body, p.Value))
	case "ldap":
		return strings.HasPrefix(signal, "ldap_error_") && ldapErrorSignal(body, baseBody)
	case "xpath":
		return strings.HasPrefix(signal, "xpath_error_") && xpathErrorSignal(body, baseBody)
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
			p.Value != "" && strings.Contains(body, p.Value)
	case "second_order":
		if p.Value != "" && strings.Contains(body, p.Value) && !strings.Contains(baseBody, p.Value) {
			return true
		}
		return differentialWithStatusGuard(body, baseBody, p.Value, probeStatus, baseStatus)
	case "git_recovery":
		return probeStatus == 200 && body != baseBody && len(strings.TrimSpace(body)) > 4 &&
			(isGitContent(body) || strings.Contains(body, "Exposed .git") || strings.Contains(body, "partial_git_exposure"))
	case "mass_assignment":
		return (strings.HasPrefix(signal, "mass_assignment_") || signal == "role_escalation" || signal == "hidden_admin_flag" || signal == "permission_injection") &&
			probeStatus >= 200 && probeStatus < 300 &&
			resourceFingerprint(body) != resourceFingerprint(baseBody)
	case "idor":
		return signal == "foreign_object_access" &&
			probeStatus >= 200 && probeStatus < 300 &&
			(baseStatus == 401 || baseStatus == 403 || !successfulResourceResponse(baseline)) &&
			successfulResourceResponse(probe)
	case "nginx_alias":
		return signal == "alias_traversal" && probeStatus == 200 && len(body) >= 50
	case "nextjs_bypass":
		return nextJSBypassSignalConfirmed(signal, body, probeStatus, baseStatus)
	case "framework_debug":
		return frameworkDebugSignalConfirmed(signal, body, probeStatus)
	case "iis_discovery":
		return (signal == "iis_shortname" && (probeStatus != baseStatus || (probeStatus == 404 && baseStatus == 404))) ||
			(signal == "iis_source_disclosure" && probeStatus == 200 &&
				(strings.Contains(body, "<%@") || strings.Contains(body, "<script runat") || strings.Contains(body, "<?php")))
	case "firebase_misconfig":
		return firebaseSignalConfirmed(signal, body, probeStatus)
	case "spring_cloud_jolokia":
		return springCloudJolokiaSignalConfirmed(signal, body, probeStatus)
	case "saas_exposure":
		return saasExposureSignalConfirmed(signal, body, probeStatus)
	case "pdf_injection":
		return pdfInjectionSignalConfirmed(signal, body, probeStatus)
	case "cpdos":
		return (probeStatus == 400 || probeStatus == 405 || probeStatus == 500 || probeStatus == 501) && baseStatus == 200
	case "proxy_path_confusion":
		return probeStatus == 200 && (baseStatus == 401 || baseStatus == 403)
	case "ws_cswsh":
		return probeStatus == 101
	case "jsonp_callback":
		return probeStatus == 200 && strings.Contains(body, p.Value)
	case "react_rsc_rce":
		return false
	case "server_side_js_injection":
		return ssjsSignalConfirmed(body, baseBody, signal, probeStatus, baseStatus)
	case "csti_detection":
		return cstiSignalConfirmed(body, baseBody, p.Value, signal, probeStatus)
	case "swagger_exposure":
		return swaggerExposureSignalConfirmed(signal, body, probeStatus)
	case "sensitive_file_discovery":
		return sensitiveFileSignalConfirmed(signal, probe)
	case "http_smuggling":
		return httpSmugglingSignalConfirmed(signal, body, p.Value, probeStatus)
	case "race_condition_sync":
		return signal == "race_condition_limit_bypass" && probeStatus >= 200 && probeStatus < 300
	case "oauth_flow_audit":
		return signal == "oauth_token_query_response" && oauthTokenInQuery(probeHeaders)
	case "cloud_native_exposure":
		return cloudNativeSignalConfirmed(signal, probeStatus, body)
	case "grpc_scan":
		return grpcSignalConfirmed(signal, probe)
	case "graphql":
		return graphqlSignalConfirmed(body, baseBody, signal, probeStatus, baseStatus)
	case "csrf":
		return signal == "cross_site_state_mutation" && probeStatus >= 200 && probeStatus < 300 &&
			resourceFingerprint(body) != resourceFingerprint(baseBody)
	case "account_enum",
		"prototype_pollution",
		"wordpress_fuzz", "websocket",
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
	body := strings.ToLower(probe.Body)
	base := strings.ToLower(baseline.Body)
	if body == base || strings.TrimSpace(body) == "" {
		return false
	}
	if strings.Contains(body, "blocked by policy") || strings.Contains(body, "is blocked") ||
		strings.Contains(body, "request blocked") || strings.Contains(body, "access denied") {
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
		default:
			signal = p.ExpectedSignal
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
		return newMarkerCount(body, base, []string{
			"compute", "vmid", "subscriptionid", "microsoft.compute", "azureenvironment",
		}) >= 1
	case "internal_ip", "protocol_smuggling":
		// Disallow matching AWS metadata markers on internal IP probes
		if strings.Contains(body, "ami-id") || strings.Contains(body, "instance-id") {
			return false
		}
		return bodyDiffRatio(base, body) >= 0.05
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
	case "file_disclosure":
		// Detect /etc/passwd or win.ini content
		lower := strings.ToLower(body)
		baseLower := strings.ToLower(baseline)
		markers := []string{"root:x:0:0:", "root:*:0:0:", "[fonts]", "[extensions]", "[mail]", "for 16-bit app support"}
		for _, m := range markers {
			if strings.Contains(lower, m) && !strings.Contains(baseLower, m) {
				return true
			}
		}
		return false
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
		return strings.EqualFold(acao, "null")
	case "origin_reflection", "partial_origin_match", "pre_domain_match", "protocol_downgrade", "trusted_subdomain",
		"localhost_origin", "cloud_metadata_origin", "intranet_origin":
		return acao == origin
	case "private_network_access":
		pna := headerCI(probeHeaders, "Access-Control-Allow-Private-Network")
		return strings.EqualFold(pna, "true") && acao != ""
	case "wildcard_credentials":
		// While browsers don't send credentials with ACAO:*, this misconfiguration
		// indicates weak CORS policy and may be exploitable with other techniques.
		return true
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
			return score < 0.70
		}
		switch module {
		case "xss", "sqli", "ssti", "xxe", "command_injection", "lfi", "ssrf", "nosql":
			return score < 0.60
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

func graphqlSignalConfirmed(body, baseBody, signal string, probeStatus, baseStatus int) bool {
	if probeStatus >= 400 {
		return false
	}
	lower := strings.ToLower(body)
	switch signal {
	case "graphql_schema_exposure":
		return strings.Contains(lower, "__schema") && strings.Contains(lower, "types")
	case "field_suggestions_exposed", "graphql_field_suggestions":
		return (strings.Contains(lower, "did you mean") || strings.Contains(lower, "perhaps you meant")) &&
			!strings.Contains(strings.ToLower(baseBody), "did you mean")
	case "graphql_field_auth_leak":
		var resp struct {
			Data map[string]interface{} `json:"data"`
		}
		if json.Unmarshal([]byte(body), &resp) != nil || len(resp.Data) == 0 {
			return false
		}
		dataBytes, _ := json.Marshal(resp.Data)
		dataStr := strings.ToLower(string(dataBytes))
		for _, kw := range []string{"apikey", "secrettoken", "ssn", "password", "token", "isadmin"} {
			if strings.Contains(dataStr, kw) && !strings.Contains(strings.ToLower(baseBody), kw) {
				if !strings.Contains(dataStr, `"`+kw+`":null`) && !strings.Contains(dataStr, `"`+kw+`":""`) {
					return true
				}
			}
		}
		return false
	case "graphql_filter_where_rce":
		return strings.Contains(body, "AKCA_GQL_9991_EVAL") || strings.Contains(body, "AKCA_ENV_object")
	case "type_inversion_data_leak":
		var resp struct {
			Data map[string]interface{} `json:"data"`
		}
		if json.Unmarshal([]byte(body), &resp) != nil || len(resp.Data) == 0 {
			return false
		}
		dataRaw, _ := json.Marshal(resp.Data)
		dataLower := strings.ToLower(string(dataRaw))
		baseLower := strings.ToLower(baseBody)
		if len(body) <= len(baseBody)*2 {
			return false
		}
		for _, kw := range []string{"email", "password", "token", "secret", "admin", "credential", "session", "oauth"} {
			if strings.Contains(dataLower, kw) && !strings.Contains(baseLower, kw) {
				return true
			}
		}
		return false
	case "type_inversion_error_disclosure":
		baseLower := strings.ToLower(baseBody)
		for _, kw := range []string{"cannot represent", "expected type", "int cannot", "validation error", "bad user input"} {
			if strings.Contains(lower, kw) && !strings.Contains(baseLower, kw) {
				return true
			}
		}
		return false
	case "graphql_sift_where_detected":
		return strings.Contains(lower, "in csp mode, sift does not support strings") ||
			strings.Contains(lower, `in "$where" condition`) ||
			strings.Contains(lower, "cannot use $where")
	case "graphql_batch_accepted":
		return strings.Count(body, `"data"`) >= 5 || strings.Count(body, `__typename`) >= 5
	case "graphql_alias_overload":
		return strings.Contains(lower, `"a1"`) && strings.Contains(lower, `"a2"`) && strings.Contains(lower, `"a5"`)
	default:
		return strings.Contains(lower, `"data"`)
	}
}
