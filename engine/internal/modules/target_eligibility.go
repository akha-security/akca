package modules

import (
	"strings"

	"github.com/akha-security/akca/engine/internal/targeting"
)

func (r *Runner) forcedActiveTarget(raw string) bool {
	return targeting.ForcedURL(raw, r.cfg.ForceActiveScanURLs)
}

func activeInputModule(module string) bool {
	return isCoreInjectionModule(module) || module == "ssrf" || module == "xxe" || module == "route_auth_bypass" || module == "ldap" || module == "xpath" || module == "server_side_js_injection"
}

func (r *Runner) activeTargetReason(module string, t ScanTarget) string {
	if !activeInputModule(module) {
		return ""
	}
	resource := targeting.Resource{URL: t.EndpointURL, Method: t.Method}
	if t.ObservedResponse != nil {
		response := t.ObservedResponse.Response
		resource.Status, resource.Body = response.StatusCode, response.Body
		for name, value := range response.Headers {
			if strings.EqualFold(name, "Content-Type") {
				resource.ContentType = value
			}
		}
	}
	resource.ForceActive = r.forcedActiveTarget(t.EndpointURL)
	resource.DynamicInput = strings.TrimSpace(t.RequestTemplate.Body) != "" || strings.TrimSpace(t.BodyTemplate) != "" ||
		(t.Profile.Confidence >= 0.5 && t.Profile.ReflectionKind != "" && t.Profile.ReflectionKind != "removed")
	return targeting.InactiveReason(resource)
}
