package app

func capturedContentModule(name string) bool {
	switch name {
	case "security_headers", "cookie_security", "sensitive_data", "secret_exposure", "script_source", "vulnerable_components":
		return true
	}
	return false
}

func coreInputModule(name string) bool {
	switch name {
	case "xss", "blind_xss", "sqli", "nosql", "ssti", "command_injection", "ssrf", "xxe", "lfi", "ldap", "xpath", "ldap_xpath_injection", "client_ssti":
		return true
	}
	return false
}

func initialModule(name string) bool {
	return capturedContentModule(name) || coreInputModule(name)
}

func scheduledModules(stage string) []vulnModulePhase {
	var initial, late, highImpact, session []vulnModulePhase
	for _, item := range fullScanModuleOrder {
		switch {
		case item.name == "session_lifecycle":
			session = append(session, item)
		case item.name == "php2shell":
			highImpact = append(highImpact, item)
		case initialModule(item.name):
			initial = append(initial, item)
		default:
			late = append(late, item)
		}
	}
	switch stage {
	case "priority":
		return initial
	case "followup":
		return append(append(initial, late...), highImpact...)
	case "session":
		return session
	default:
		return append(append(append(initial, late...), highImpact...), session...)
	}
}
