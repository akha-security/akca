package report

import "strings"

// taxonomyFor provides stable, report-level classification without changing
// module execution. Unknown/custom modules remain unclassified rather than
// receiving a misleading generic category.
func taxonomyFor(vulnClass, signal string) ([]string, []string) {
	class := strings.ToLower(strings.TrimSpace(vulnClass))
	value := class + " " + strings.ToLower(signal)
	match := func(parts ...string) bool {
		for _, part := range parts {
			if strings.Contains(value, part) {
				return true
			}
		}
		return false
	}
	switch {
	case match("sqli"):
		return []string{"CWE-89"}, []string{"A05:2025 Injection"}
	case match("xss", "csti"):
		return []string{"CWE-79"}, []string{"A05:2025 Injection"}
	case match("command_injection", "server_side_js_injection"):
		return []string{"CWE-78"}, []string{"A05:2025 Injection"}
	case match("ssti", "ldap", "xpath", "xxe", "crlf", "hpp", "prototype_pollution", "pdf_injection", "llm_injection"):
		return []string{"CWE-74"}, []string{"A05:2025 Injection"}
	case match("ssrf"):
		return []string{"CWE-918"}, []string{"A01:2025 Broken Access Control"}
	case match("idor", "bfla", "tenant_isolation", "route_auth_bypass"):
		return []string{"CWE-862"}, []string{"A01:2025 Broken Access Control"}
	case match("csrf"):
		return []string{"CWE-352"}, []string{"A01:2025 Broken Access Control"}
	case match("lfi", "path_traversal", "proxy_path_confusion", "nginx_alias"):
		return []string{"CWE-22"}, []string{"A01:2025 Broken Access Control"}
	case match("open_redirect"):
		return []string{"CWE-601"}, []string{"A01:2025 Broken Access Control"}
	case match("known_cve", "vulnerable_components", "script_source", "cicd_exposure"):
		return []string{"CWE-1104"}, []string{"A03:2025 Software Supply Chain Failures"}
	case match("tls_misconfig"):
		return []string{"CWE-326"}, []string{"A04:2025 Cryptographic Failures"}
	case match("cookie_security", "sensitive_data", "secret_exposure"):
		return []string{"CWE-319"}, []string{"A04:2025 Cryptographic Failures"}
	case match("broken_auth", "improper_auth", "account_enum", "account_recovery", "jwt", "oauth", "session_lifecycle"):
		return []string{"CWE-287"}, []string{"A07:2025 Authentication Failures"}
	case match("insecure_deserialization"):
		return []string{"CWE-502"}, []string{"A08:2025 Software or Data Integrity Failures"}
	case match("smuggling", "parser_differential"):
		return []string{"CWE-444"}, []string{"A10:2025 Mishandling of Exceptional Conditions"}
	case match("security_headers", "cors", "debug", "exposure", "backup_archives", "http_methods", "cloud_posture", "firebase_misconfig", "swagger"):
		return []string{"CWE-16"}, []string{"A02:2025 Security Misconfiguration"}
	case match("business_logic", "mass_assignment", "race_condition", "rate_limit", "file_upload", "webhook_security", "cache_deception", "cache_poisoning"):
		return []string{"CWE-840"}, []string{"A06:2025 Insecure Design"}
	default:
		return nil, nil
	}
}
