package findingtext

import (
	"fmt"
	"strings"
)

var humanTitles = map[string]string{
	"sqli":                "SQL Injection",
	"nosql":               "NoSQL Injection",
	"xss":                 "Cross-Site Scripting (XSS)",
	"blind_xss":           "Blind Cross-Site Scripting (XSS)",
	"ssti":                "Server-Side Template Injection",
	"client_ssti":         "Client-Side Template Injection",
	"command_injection":   "OS Command Injection",
	"xxe":                 "XML External Entity (XXE)",
	"ssrf":                "Server-Side Request Forgery (SSRF)",
	"lfi":                 "Local File Inclusion",
	"idor":                "Insecure Direct Object Reference (IDOR)",
	"bfla":                "Broken Function Level Authorization",
	"open_redirect":       "Open Redirect",
	"secret_exposure":     "Exposed Secret",
	"cors":                "CORS Misconfiguration",
	"csrf":                "Cross-Site Request Forgery (CSRF)",
	"graphql":             "GraphQL Security Issue",
	"crlf":                "CRLF Injection",
	"jwt":                 "JWT Security Issue",
	"file_upload":         "Unsafe File Upload",
	"prototype_pollution": "Prototype Pollution",
	"second_order":        "Second-Order Injection",
	"nosql_injection":     "NoSQL Injection",
}

// HumanTitle returns a user-facing vulnerability name (e.g. "SQL Injection").
func HumanTitle(vulnClass string) string {
	key := strings.ToLower(strings.TrimSpace(vulnClass))
	if t, ok := humanTitles[key]; ok {
		return t
	}
	return prettifyClass(key)
}

// DisplayTitle prefers the human title for a vuln class; falls back to stored title.
func DisplayTitle(vulnClass, storedTitle string) string {
	if t := HumanTitle(vulnClass); t != prettifyClass(strings.ToLower(vulnClass)) || storedTitle == "" {
		return t
	}
	if looksTechnicalTitle(storedTitle) {
		return HumanTitle(vulnClass)
	}
	return storedTitle
}

func looksTechnicalTitle(title string) bool {
	lower := strings.ToLower(title)
	return strings.Contains(lower, "_signal") ||
		strings.Contains(lower, "(") && strings.Contains(lower, ") on ") ||
		strings.HasPrefix(lower, "sqli ") ||
		strings.HasPrefix(lower, "ssti ") ||
		strings.Contains(lower, "math_evaluation")
}

// HumanDescription builds a readable description; technical signal details go here.
func HumanDescription(module, signal, param, endpoint, payload, variant, location string) string {
	title := HumanTitle(module)
	var parts []string
	if param != "" && endpoint != "" {
		loc := ""
		if location != "" {
			loc = fmt.Sprintf(" (%s)", location)
		}
		parts = append(parts, fmt.Sprintf("%s was detected on parameter %q%s at %s.", title, param, loc, endpoint))
	} else if endpoint != "" {
		parts = append(parts, fmt.Sprintf("%s was detected at %s.", title, endpoint))
	} else {
		parts = append(parts, fmt.Sprintf("%s was detected during automated scanning.", title))
	}
	if payload != "" {
		parts = append(parts, fmt.Sprintf("Payload tested: %s", truncate(payload, 500)))
	}
	if signal != "" {
		parts = append(parts, fmt.Sprintf("Evidence: %s.", formatSignal(signal)))
	}
	if variant != "" && variant != signal {
		parts = append(parts, fmt.Sprintf("Variant: %s.", variant))
	}
	return strings.Join(parts, " ")
}

func formatSignal(signal string) string {
	switch strings.ToLower(signal) {
	case "union_signal":
		return "independent UNION SELECT sentinel sets returned as database-result data"
	case "error_based", "error_trace":
		return "database or template error message in the response"
	case "boolean_differential", "boolean_length":
		return "boolean-based response difference compared to baseline"
	case "boolean_pair_confirmed":
		return "alternating true/false SQL predicates reproduced with stable, non-reflected responses"
	case "stacked_differential", "stacked_timing":
		return "stacked query execution confirmed via differential or timing signal"
	case "oob_sqli":
		return "out-of-band DNS/HTTP callback via Interactsh (OAST) correlation"
	case "timing_differential", "timing_signal":
		return "time-based response delay consistent with injection"
	case "math_evaluation", "template_evaluation_49":
		return "server-side template evaluated arithmetic expression"
	case "reflected", "dom_xss", "stored":
		return "user-controlled input reflected or executed in the page"
	case "blind_oast", "rfi_oast", "blind_xss_oast_callback":
		return "out-of-band callback received via Interactsh (OAST) correlation"
	default:
		return strings.ReplaceAll(signal, "_", " ")
	}
}

func prettifyClass(s string) string {
	if s == "" {
		return "Security Finding"
	}
	words := strings.Split(strings.ReplaceAll(s, "_", " "), " ")
	for i, w := range words {
		if len(w) == 0 {
			continue
		}
		words[i] = strings.ToUpper(w[:1]) + strings.ToLower(w[1:])
	}
	return strings.Join(words, " ")
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
