package verification

import "strings"

func DetectHoneypot(canaries []string, bodies []string) bool {
	if len(canaries) < 3 || len(bodies) < 3 || len(canaries) != len(bodies) {
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
