package params

import (
	"net/http"
	"net/url"
	"strings"
)

var staticExtensions = []string{
	".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
	".woff", ".woff2", ".ttf", ".eot", ".map", ".pdf", ".zip", ".mp4", ".mp3",
}

// ShouldDiscoverEndpoint reports whether an endpoint is worth active parameter probing.
func ShouldDiscoverEndpoint(endpointURL, method string) bool {
	if IsStaticAsset(endpointURL) {
		return false
	}
	lower := strings.ToLower(endpointURL)
	if strings.Contains(lower, "/static/") || strings.Contains(lower, "/assets/") ||
		strings.Contains(lower, "/_next/static/") {
		return false
	}
	return true
}

// IsStaticAsset returns true for URLs that rarely expose hidden parameters.
func IsStaticAsset(endpointURL string) bool {
	u, err := url.Parse(endpointURL)
	if err != nil {
		return false
	}
	path := strings.ToLower(u.Path)
	for _, ext := range staticExtensions {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// PassiveEnoughForSkip returns true when passive extraction already found sufficient params.
func PassiveEnoughForSkip(passive []DiscoveredParameter, method string) bool {
	// POST/PUT/PATCH endpoints always get active multi-surface probing.
	if m := strings.ToUpper(method); m == http.MethodPost || m == http.MethodPut || m == http.MethodPatch {
		return false
	}
	if len(passive) >= 8 {
		return true
	}
	high := 0
	for _, p := range passive {
		if p.Priority >= 90 || p.Source == "passive" && p.Confidence >= 0.85 {
			high++
		}
	}
	return high >= 3
}
