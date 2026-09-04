package fingerprint

import (
	"net/http"
	"strings"

	"github.com/akha-security/akca/engine/internal/models"
)

// ClassifyEndpoint builds endpoint intelligence from a captured request/response pair.
func ClassifyEndpoint(url, method, contentType, body string, waf *models.WAFProfile, tech *models.TechFingerprint) models.EndpointIntelligence {
	intel := models.EndpointIntelligence{
		URL:             url,
		Method:          strings.ToUpper(method),
		ContentType:     contentType,
		WAFProfile:      waf,
		TechFingerprint: tech,
	}

	intel.EndpointType = detectEndpointType(url, contentType, body)
	intel.AuthRequired = detectAuthRequired(url, body)
	intel.StateChanging = isStateChanging(method)
	intel.RiskTags = buildRiskTags(intel)
	intel.RecommendedModules = recommendModules(intel, waf, tech)
	return intel
}

func detectEndpointType(url, contentType, body string) string {
	lowerURL := strings.ToLower(url)
	ct := strings.ToLower(contentType)
	switch {
	case strings.Contains(lowerURL, "/graphql"):
		return "graphql"
	case strings.HasPrefix(lowerURL, "ws://") || strings.HasPrefix(lowerURL, "wss://"):
		return "websocket"
	case strings.Contains(ct, "application/json") || strings.Contains(lowerURL, "/api/"):
		return "api"
	case strings.Contains(ct, "text/html") || strings.Contains(body, "<html"):
		return "html"
	case strings.Contains(ct, "javascript"):
		return "script"
	default:
		return "unknown"
	}
}

func detectAuthRequired(url, body string) bool {
	lower := strings.ToLower(url + " " + body)
	keywords := []string{"/login", "/auth", "/oauth", "/session", "unauthorized", "sign in", "authenticate"}
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func isStateChanging(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func buildRiskTags(intel models.EndpointIntelligence) []string {
	var tags []string
	if intel.AuthRequired {
		tags = append(tags, "auth")
	}
	if intel.StateChanging {
		tags = append(tags, "state-changing")
	}
	switch intel.EndpointType {
	case "api", "graphql":
		tags = append(tags, "api-surface")
	case "html":
		tags = append(tags, "user-input")
	}
	if intel.WAFProfile != nil && intel.WAFProfile.Vendor != "" {
		tags = append(tags, "waf-protected")
	}
	return tags
}

func recommendModules(intel models.EndpointIntelligence, waf *models.WAFProfile, tech *models.TechFingerprint) []string {
	modules := make([]string, 0, 8)
	add := func(name string) {
		for _, existing := range modules {
			if existing == name {
				return
			}
		}
		modules = append(modules, name)
	}

	switch intel.EndpointType {
	case "api", "graphql":
		add("idor")
		add("sqli")
		add("nosql")
		add("ssrf")
		add("lfi")
		add("command_injection")
		if intel.EndpointType == "graphql" {
			add("graphql")
		}
	case "html", "web", "unknown":
		add("sqli")
		add("xss")
		add("ssrf")
		add("lfi")
		add("open_redirect")
		add("command_injection")
	case "websocket":
		add("websocket")
	}
	// WAF intelligence may change pacing and payload ordering, but it must not
	// remove scanner capabilities from the recommendation set.
	_ = waf
	return modules
}
