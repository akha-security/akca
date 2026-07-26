package fuzzing

import "strings"

func ClassifyStatusCode(code int) string {
	switch {
	case code == 200:
		return "ok"
	case code >= 300 && code < 400:
		return "redirect"
	case code == 401:
		return "unauthorized"
	case code == 403:
		return "forbidden"
	case code == 404:
		return "not_found"
	case code == 405:
		return "method_not_allowed"
	case code == 429:
		return "rate_limited"
	case code >= 500:
		return "server_error"
	default:
		return "other"
	}
}

func ClassifySignal(code int, isSoft404, isArchive bool) string {
	if isArchive && code == 200 {
		return "archive_exposure"
	}
	if isSoft404 {
		return "soft_404"
	}
	return ClassifyStatusCode(code)
}

func Score403Priority(url, method string) int {
	score := 10
	lower := strings.ToLower(url)
	keywords := []struct {
		word  string
		bonus int
	}{
		{"/admin", 50}, {"/api/", 40}, {"/manage", 35}, {"/actuator", 45},
		{"/config", 30}, {"/env", 30}, {"/internal", 25}, {"/dashboard", 20},
	}
	for _, kw := range keywords {
		if strings.Contains(lower, kw.word) {
			score += kw.bonus
		}
	}
	if method != "GET" && method != "" {
		score += 5
	}
	if score > 200 {
		return 200
	}
	return score
}
