package modules

import (
	"net/url"
	"strings"
)

// technologySurface is the single source of truth used by platform-specific
// modules. Fingerprinting used to be persisted but server/CDN and JavaScript
// framework evidence never reached module preconditions, so expensive probes
// silently degraded to "run everywhere".
func technologySurface(t ScanTarget) string {
	tech := t.Payloads.Tech
	parts := []string{
		tech.BackendLanguage,
		tech.Framework,
		tech.Database,
		tech.ServerCDN,
		tech.JSFramework,
		strings.Join(tech.Hints, " "),
		t.EndpointType,
		t.Profile.ContentType,
		string(t.Profile.Context),
	}
	if t.ObservedResponse != nil {
		body := t.ObservedResponse.Response.Body
		if len(body) > 64*1024 {
			body = body[:64*1024]
		}
		parts = append(parts,
			t.ObservedResponse.Response.Headers["Server"],
			t.ObservedResponse.Response.Headers["server"],
			t.ObservedResponse.Response.Headers["X-Powered-By"],
			t.ObservedResponse.Response.Headers["x-powered-by"],
			body,
		)
	}
	return strings.ToLower(strings.Join(parts, " "))
}

func hasTechnology(t ScanTarget, markers ...string) bool {
	surface := technologySurface(t)
	for _, marker := range markers {
		if strings.Contains(surface, strings.ToLower(marker)) {
			return true
		}
	}
	return false
}

func technologyFingerprintKnown(t ScanTarget) bool {
	tech := t.Payloads.Tech
	if backendTechnologyKnown(t) || webServerTechnologyKnown(t) || strings.TrimSpace(tech.JSFramework) != "" {
		return true
	}
	for _, hint := range tech.Hints {
		lower := strings.ToLower(strings.TrimSpace(hint))
		if strings.HasPrefix(lower, "js:") {
			return true
		}
	}
	return false
}

// Backend, origin-server and frontend fingerprints answer different questions.
// A CDN banner or React marker must not be treated as proof that the origin
// runtime is known; doing so suppresses unrelated bounded capability probes.
func backendTechnologyKnown(t ScanTarget) bool {
	tech := t.Payloads.Tech
	if strings.TrimSpace(tech.BackendLanguage) != "" || strings.TrimSpace(tech.Framework) != "" {
		return true
	}
	for _, hint := range tech.Hints {
		lower := strings.ToLower(strings.TrimSpace(hint))
		if strings.HasPrefix(lower, "backend:") || strings.HasPrefix(lower, "framework:") {
			return true
		}
	}
	if t.ObservedResponse == nil {
		return false
	}
	headers := t.ObservedResponse.Response.Headers
	return strings.TrimSpace(headers["X-Powered-By"]) != "" || strings.TrimSpace(headers["x-powered-by"]) != ""
}

func webServerTechnologyKnown(t ScanTarget) bool {
	values := []string{t.Payloads.Tech.ServerCDN}
	for _, hint := range t.Payloads.Tech.Hints {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(hint)), "server:") {
			values = append(values, hint)
		}
	}
	if t.ObservedResponse != nil {
		headers := t.ObservedResponse.Response.Headers
		values = append(values, headers["Server"], headers["server"])
	}
	combined := strings.ToLower(strings.Join(values, " "))
	for _, marker := range []string{"nginx", "apache", "microsoft-iis", "litespeed", "tomcat", "caddy", "envoy"} {
		if strings.Contains(combined, marker) {
			return true
		}
	}
	return false
}

func jsFrameworkTechnologyKnown(t ScanTarget) bool {
	if strings.TrimSpace(t.Payloads.Tech.JSFramework) != "" {
		return true
	}
	for _, hint := range t.Payloads.Tech.Hints {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(hint)), "js:") {
			return true
		}
	}
	return false
}

func nginxReady(t ScanTarget) (bool, string) {
	if !hasTechnology(t, "nginx") && webServerTechnologyKnown(t) {
		return false, "nginx technology not detected"
	}
	if !likelyNginxAliasPath(t.EndpointURL) {
		return false, "no observed alias-like directory path"
	}
	return true, ""
}

func likelyNginxAliasPath(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	segment := strings.ToLower(firstNginxPathSegment(u.Path))
	if segment == "" {
		return false
	}
	switch segment {
	case "static", "assets", "asset", "uploads", "upload", "images", "image", "img",
		"css", "js", "fonts", "media", "files", "content", "resources", "public",
		"dist", "build", "downloads", "download", "storage":
		return true
	default:
		return false
	}
}

func iisReady(t ScanTarget) (bool, string) {
	if hasTechnology(t, "microsoft-iis", "server:iis", "asp.net", "aspnet", "__viewstate", "asp.net_sessionid") || !webServerTechnologyKnown(t) {
		return true, ""
	}
	return false, "Microsoft IIS/ASP.NET technology not detected"
}

func nextJSReady(t ScanTarget) (bool, string) {
	if hasTechnology(t, "next.js", "nextjs", "__next_data__", "/_next/") ||
		(!backendTechnologyKnown(t) && !jsFrameworkTechnologyKnown(t)) {
		return true, ""
	}
	return false, "Next.js technology not detected"
}

func reactRSCReady(t ScanTarget) (bool, string) {
	if hasTechnology(t, "next.js", "nextjs", "react", "__next_data__", "react-server") ||
		(!backendTechnologyKnown(t) && !jsFrameworkTechnologyKnown(t)) {
		return true, ""
	}
	return false, "React/Next.js technology not detected"
}

func springReady(t ScanTarget) (bool, string) {
	if hasTechnology(t, "spring", "spring boot", "x-application-context", "jolokia") || !backendTechnologyKnown(t) {
		return true, ""
	}
	return false, "Spring/Jolokia technology not detected"
}

func serverSideJSReady(t ScanTarget) (bool, string) {
	if ok, reason := hasParameter(t); !ok {
		return false, reason
	}
	if hasTechnology(t, "node.js", "nodejs", "express", "next.js", "nextjs") {
		return true, ""
	}
	if backendTechnologyKnown(t) {
		return false, "server-side JavaScript runtime not detected"
	}
	if likelyServerSideJSSurface(t) {
		return true, ""
	}
	return false, "no Node.js evidence or code-evaluation semantics"
}

func frameworkDebugReady(t ScanTarget) (bool, string) {
	if hasTechnology(t, "flask", "werkzeug", "laravel", "django", "fastapi", "rails", "ruby on rails") || !backendTechnologyKnown(t) {
		return true, ""
	}
	return false, "supported debug framework not detected"
}

func firebaseReady(t ScanTarget) (bool, string) {
	surface := technologySurface(t) + " " + strings.ToLower(t.EndpointURL)
	if strings.Contains(surface, "firebaseio.com") ||
		strings.Contains(surface, "firebasestorage.googleapis.com") ||
		strings.Contains(surface, ".appspot.com") ||
		strings.Contains(surface, "firebase") {
		return true, ""
	}
	if !technologyFingerprintKnown(t) {
		return true, ""
	}
	return false, "Firebase endpoint evidence not detected"
}

func saasReady(t ScanTarget) (bool, string) {
	surface := technologySurface(t) + " " + strings.ToLower(t.EndpointURL)
	for _, marker := range []string{"servicenow", "service-now.com", "salesforce", "force.com", "lightning.force.com", "/aura"} {
		if strings.Contains(surface, marker) {
			return true, ""
		}
	}
	if !technologyFingerprintKnown(t) {
		return true, ""
	}
	return false, "ServiceNow/Salesforce evidence not detected"
}

func wordpressReady(t ScanTarget) (bool, string) {
	lower := strings.ToLower(t.EndpointURL)
	if strings.Contains(lower, "wp-") || strings.Contains(lower, "wordpress") ||
		hasTechnology(t, "wordpress", "wp-content", "wp-includes") {
		return true, ""
	}
	return false, "WordPress technology not detected"
}

func pdfReady(t ScanTarget) (bool, string) {
	if ok, reason := hasParameter(t); !ok {
		return false, reason
	}
	surface := strings.ToLower(strings.Join([]string{t.Parameter, t.EndpointURL, t.Profile.ContentType}, " "))
	for _, marker := range pdfParamHints {
		if strings.Contains(surface, marker) {
			return true, ""
		}
	}
	return false, "no PDF generation/rendering semantics detected"
}

func cstiReady(t ScanTarget) (bool, string) {
	if ok, reason := hasParameter(t); !ok {
		return false, reason
	}
	if hasTechnology(t, "angular", "vue", "svelte", "alpine", "polymer", "lodash", "underscore", "ejs") {
		return true, ""
	}
	if !technologyFingerprintKnown(t) || strings.Contains(strings.ToLower(string(t.Profile.Context)), "html") {
		return true, ""
	}
	return false, "client-side template framework not detected"
}

func graphqlReady(t ScanTarget) (bool, string) {
	surface := strings.ToLower(strings.Join([]string{t.EndpointURL, t.EndpointType, t.Profile.ContentType}, " "))
	if strings.Contains(surface, "graphql") || strings.Contains(surface, "application/graphql") {
		return true, ""
	}
	return false, "GraphQL endpoint evidence not detected"
}

func websocketReady(t ScanTarget) (bool, string) {
	u, err := url.Parse(t.EndpointURL)
	if err == nil && (strings.EqualFold(u.Scheme, "ws") || strings.EqualFold(u.Scheme, "wss")) {
		return true, ""
	}
	surface := strings.ToLower(strings.Join([]string{t.EndpointURL, t.EndpointType}, " "))
	for _, marker := range []string{"websocket", "/ws", "/socket", "sockjs"} {
		if strings.Contains(surface, marker) {
			return true, ""
		}
	}
	if !technologyFingerprintKnown(t) {
		return true, ""
	}
	return false, "WebSocket endpoint evidence not detected"
}

func grpcReady(t ScanTarget) (bool, string) {
	surface := strings.ToLower(strings.Join([]string{t.EndpointURL, t.EndpointType, t.Profile.ContentType}, " "))
	if strings.Contains(surface, "grpc") || strings.Contains(surface, "protobuf") || strings.Contains(surface, "application/proto") {
		return true, ""
	}
	if !technologyFingerprintKnown(t) {
		return true, ""
	}
	return false, "gRPC/protobuf endpoint evidence not detected"
}

func oauthFlowReady(t ScanTarget) (bool, string) {
	surface := strings.ToLower(t.EndpointURL)
	for _, marker := range []string{"oauth", "openid", "oidc", "/authorize", "/token", "/callback", "/sso"} {
		if strings.Contains(surface, marker) {
			return true, ""
		}
	}
	return false, "OAuth/OIDC endpoint evidence not detected"
}
