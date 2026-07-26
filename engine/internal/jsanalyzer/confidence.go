package jsanalyzer

import (
	"regexp"
	"strings"
)

var dynamicSeg = regexp.MustCompile(`/:id|/\{[^}]+\}|/\[[^\]]+\]|/\d+`)

func NormalizeTemplate(raw string) string {
	t := strings.TrimSpace(raw)
	t = dynamicSeg.ReplaceAllString(t, "/:id")
	for strings.Contains(t, "//") {
		t = strings.ReplaceAll(t, "//", "/")
	}
	return t
}

func ScoreEndpoint(raw, extraction, method string) float64 {
	score := 0.45
	if strings.HasPrefix(raw, "/api/") || strings.Contains(strings.ToLower(raw), "graphql") {
		score += 0.25
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		score += 0.15
	}
	if extraction == "ast" {
		score += 0.1
	}
	if method != "" && method != "GET" {
		score += 0.05
	}
	if len(raw) < 4 || strings.Count(raw, "/") == 0 {
		score -= 0.2
	}
	if score > 1 {
		return 1
	}
	if score < 0 {
		return 0
	}
	return score
}

func FilterByConfidence(endpoints []ExtractedEndpoint, min float64) []ExtractedEndpoint {
	if min <= 0 {
		min = MinConfidence
	}
	out := make([]ExtractedEndpoint, 0, len(endpoints))
	for _, ep := range endpoints {
		if ep.Confidence >= min {
			out = append(out, ep)
		}
	}
	return out
}
