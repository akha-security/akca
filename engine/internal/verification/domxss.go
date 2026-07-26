package verification

import "strings"

func CheckDOMPresence(html, payload string) bool {
	return strings.Contains(html, payload)
}

func CheckDOMExecution(html string) bool {
	return strings.Contains(strings.ToLower(html), `data-akca-xss="executed"`)
}

func DOMXSSPayload() string {
	return `<script>document.documentElement.setAttribute('data-akca-xss','executed')</script>`
}

func SeparateDOMExecution(present, executed bool) (ConfidenceLevel, DowngradeReason) {
	if executed {
		return Confirmed, ""
	}
	if present {
		return Potential, ReasonDOMPresenceOnly
	}
	return NeedsManualReview, ""
}
