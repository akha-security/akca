package verification

// RequiresDifferentialEvidence reports whether a module needs a meaningful
// probe-vs-baseline change rather than static/content-only detection.
func RequiresDifferentialEvidence(module string) bool {
	switch module {
	case "security_headers", "tls_misconfig", "rate_limit", "api_exposure", "api_versioning",
		"secret_exposure", "sensitive_data", "cicd_exposure", "git_recovery",
		"source_code_disclosure", "cloud_storage", "cloud_posture", "vulnerable_components", "":
		return false
	default:
		return true
	}
}

func candidateModule(c Candidate) string {
	if c.Module != "" {
		return c.Module
	}
	return c.VulnClass
}
