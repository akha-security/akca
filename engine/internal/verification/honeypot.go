package verification

import "strings"

func DetectHoneypot(canaries []string, bodies []string) bool {
	// Two distinct canary/response pairs are sufficient to detect a parameter
	// that blindly echoes any input. Requiring three missed honeypots when
	// the payload budget was tight.
	if len(canaries) < 2 || len(bodies) < 2 || len(canaries) != len(bodies) {
		return false
	}
	for i, c := range canaries {
		if !strings.Contains(bodies[i], c) {
			return false
		}
	}
	normalized := normalizeReflection(bodies[0], canaries[0])
	for i := 1; i < len(bodies); i++ {
		if normalizeReflection(bodies[i], canaries[i]) != normalized {
			return false
		}
	}
	return true
}

func normalizeReflection(body, canary string) string {
	return strings.TrimSpace(strings.ReplaceAll(body, canary, "<ECHO>"))
}
