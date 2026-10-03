package verification

import "strings"

func CheckDOMPresence(html, payload string) bool {
	return strings.Contains(html, payload)
}

// CheckDOMExecution looks for any of the known AKCA XSS execution markers.
// Multiple markers are checked so that detection succeeds even when a CSP
// policy blocks one vector (e.g. inline script) but allows another (e.g.
// event handlers that modify the DOM).
func CheckDOMExecution(html string) bool {
	lower := strings.ToLower(html)
	for _, marker := range domXSSMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

var domXSSMarkers = []string{
	`data-akca-xss="executed"`,
	`data-akca-xss='executed'`,
	`class="akca-xss-confirmed"`,
	`id="akca-xss-confirmed"`,
}

// DOMXSSPayloads returns the primary payload and alternative payloads that
// use different DOM mutation techniques to handle various CSP configurations.
func DOMXSSPayloads() []string {
	return []string{
		`<script>document.documentElement.setAttribute('data-akca-xss','executed')</script>`,
		`<img src=x onerror="document.documentElement.setAttribute('data-akca-xss','executed')">`,
		`<svg/onload="document.documentElement.className='akca-xss-confirmed'">`,
		`<details open ontoggle="document.documentElement.id='akca-xss-confirmed'">`,
	}
}

// DOMXSSPayload returns the primary DOM XSS verification payload.
// Kept for backward compatibility.
func DOMXSSPayload() string {
	return DOMXSSPayloads()[0]
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
