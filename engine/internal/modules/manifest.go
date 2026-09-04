package modules

import (
	"strings"

	"github.com/akha-security/akca/engine/internal/models"
)

type ModuleDescriptor struct {
	Manifest     models.PluginManifest `json:"manifest"`
	Precondition func(ScanTarget) (bool, string)
}

var GroupBRegistry = []ModuleDescriptor{
	{
		Manifest:     models.PluginManifest{Name: "ssrf", Description: "Server-side request forgery with OAST", Version: "0.1.0"},
		Precondition: ssrfReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "xxe", Description: "XML external entity injection", Version: "0.1.0"},
		Precondition: xxeReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "lfi", Description: "Local/remote file inclusion and path traversal", Version: "0.1.0"},
		Precondition: lfiReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "file_upload", Description: "File upload risk detection", Version: "0.1.0"},
		Precondition: alwaysReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "idor", Description: "Insecure direct object reference / BOLA", Version: "0.1.0"},
		Precondition: hasParameter,
	},
	{
		Manifest:     models.PluginManifest{Name: "bfla", Description: "Broken function-level authorization", Version: "0.1.0"},
		Precondition: alwaysReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "open_redirect", Description: "Open redirect detection", Version: "0.1.0"},
		Precondition: openRedirectReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "host_header", Description: "Host header injection", Version: "0.1.0"},
		Precondition: alwaysReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "second_order", Description: "Second-order injection tracking", Version: "0.1.0"},
		Precondition: hasStoredMarker,
	},
	{
		Manifest:     models.PluginManifest{Name: "nginx_alias", Description: "Nginx off-by-slash alias traversal detection", Version: "0.1.0"},
		Precondition: alwaysReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "nextjs_bypass", Description: "Next.js middleware bypass and image SSRF detection", Version: "0.1.0"},
		Precondition: alwaysReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "framework_debug", Description: "Framework debuggers and devtools exposure detection", Version: "0.1.0"},
		Precondition: alwaysReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "iis_discovery", Description: "IIS shortname and extension confusion detection", Version: "0.1.0"},
		Precondition: alwaysReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "firebase_misconfig", Description: "Firebase RTDB and Storage misconfiguration detection", Version: "0.1.0"},
		Precondition: alwaysReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "spring_cloud_jolokia", Description: "Spring Cloud Config and Jolokia exposure detection", Version: "0.1.0"},
		Precondition: alwaysReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "saas_exposure", Description: "ServiceNow and Salesforce exposure detection", Version: "0.1.0"},
		Precondition: alwaysReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "cpdos", Description: "Cache-Poisoned Denial of Service detection", Version: "0.1.0"},
		Precondition: alwaysReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "proxy_path_confusion", Description: "Reverse proxy path confusion bypass detection", Version: "0.1.0"},
		Precondition: alwaysReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "ws_cswsh", Description: "Cross-Site WebSocket Hijacking detection", Version: "0.1.0"},
		Precondition: alwaysReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "pdf_injection", Description: "PDF generation SSRF and LFI injection detection", Version: "0.1.0"},
		Precondition: alwaysReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "jsonp_callback", Description: "JSONP callback injection and XSSI detection", Version: "0.1.0"},
		Precondition: hasParameter,
	},
	{
		Manifest:     models.PluginManifest{Name: "react_rsc_rce", Description: "React Server Components RCE detection", Version: "0.1.0"},
		Precondition: alwaysReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "server_side_js_injection", Description: "Server-Side JavaScript injection detection", Version: "0.1.0"},
		Precondition: hasParameter,
	},
	{
		Manifest:     models.PluginManifest{Name: "csti_detection", Description: "Client-Side Template Injection detection", Version: "0.1.0"},
		Precondition: hasParameter,
	},
	{
		Manifest:     models.PluginManifest{Name: "swagger_exposure", Description: "Swagger and OpenAPI specification exposure detection", Version: "0.1.0"},
		Precondition: alwaysReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "sensitive_file_discovery", Description: "Sensitive configuration and metadata file discovery", Version: "0.1.0"},
		Precondition: alwaysReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "http_smuggling", Description: "HTTP/1.1 and HTTP/2 request smuggling detection", Version: "0.1.0"},
		Precondition: alwaysReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "race_condition_sync", Description: "Synchronized single-packet race condition detection", Version: "0.1.0"},
		Precondition: alwaysReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "oauth_flow_audit", Description: "OAuth 2.0 and OIDC flow security auditing", Version: "0.1.0"},
		Precondition: alwaysReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "cloud_native_exposure", Description: "Cloud native, container and cluster API exposure detection", Version: "0.1.0"},
		Precondition: alwaysReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "grpc_scan", Description: "gRPC and gRPC-Web protocol security auditor", Version: "0.1.0"},
		Precondition: alwaysReady,
	},
}

func endpointTypes(types ...string) func(ScanTarget) (bool, string) {
	return func(t ScanTarget) (bool, string) {
		for _, hint := range types {
			if stringsContains(t.EndpointURL, hint) {
				return true, ""
			}
		}
		return false, "endpoint type mismatch"
	}
}

func contentTypes(types ...string) func(ScanTarget) (bool, string) {
	return func(t ScanTarget) (bool, string) {
		ct := stringsToLower(t.Profile.ContentType)
		for _, hint := range types {
			if stringsContains(ct, hint) || stringsContains(t.EndpointURL, hint) {
				return true, ""
			}
		}
		return false, "content type mismatch"
	}
}

func pathContains(parts ...string) func(ScanTarget) (bool, string) {
	return func(t ScanTarget) (bool, string) {
		lower := stringsToLower(t.EndpointURL)
		for _, p := range parts {
			if stringsContains(lower, p) {
				return true, ""
			}
		}
		return false, "path pattern mismatch"
	}
}

func paramLike(names ...string) func(ScanTarget) (bool, string) {
	return func(t ScanTarget) (bool, string) {
		lower := stringsToLower(t.Parameter)
		for _, n := range names {
			if lower == n || stringsContains(lower, n) {
				return true, ""
			}
		}
		return false, "parameter name mismatch"
	}
}

func openRedirectReady(t ScanTarget) (bool, string) {
	if ok, reason := hasParameter(t); !ok {
		return false, reason
	}
	if isLikelyOpenRedirectParam(t.Parameter) {
		return true, ""
	}
	return false, "non-redirect parameter skipped"
}

func lfiReady(t ScanTarget) (bool, string) {
	if ok, reason := hasParameter(t); !ok {
		return false, reason
	}
	if isLikelyLFIParam(t.Parameter) {
		return true, ""
	}
	return false, "non-file/path parameter skipped"
}

func ssrfReady(t ScanTarget) (bool, string) {
	if ok, _ := paramLike(
		"url", "uri", "link", "src", "source", "target", "dest", "redirect",
		"callback", "webhook", "feed", "image", "avatar", "proxy", "endpoint",
		"host", "domain", "fetch", "remote", "resource", "load", "preview",
		"href", "address", "server", "site", "return", "next", "continue",
		"path", "page_url", "target_url", "dest_url", "file_url", "link_url", "image_src", "avatar_url",
		"thumbnail", "download", "import_url", "webhook_url", "hook", "ping",
		"notify",
	)(t); ok {
		return true, ""
	}
	if ok, _ := pathContains(
		"ssrf", "fetch", "proxy", "webhook", "callback", "preview", "import",
		"image", "avatar", "feed", "redirect", "render", "remote",
	)(t); ok {
		return true, ""
	}
	if value := strings.ToLower(strings.TrimSpace(nativeTargetValue(t))); strings.HasPrefix(value, "http://") ||
		strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "//") {
		return true, ""
	}
	return false, "no server-side fetch semantics detected"
}

func xxeReady(t ScanTarget) (bool, string) {
	surface := strings.ToLower(strings.Join([]string{
		t.Profile.ContentType, t.EndpointURL, t.EndpointType, t.Parameter,
		t.Location, t.Profile.ParameterLocation,
	}, " "))
	for _, hint := range []string{
		"xml", "soap", "json", "svg", "rss", "atom", "feed", "docx", "xlsx",
		"wordprocessingml", "spreadsheetml", "multipart", "upload", "import", "attachment",
	} {
		if strings.Contains(surface, hint) {
			return true, ""
		}
	}
	// Also allow XXE on POST/PUT endpoints with body parameters,
	// as they may accept XML via content-type switching.
	loc := strings.ToLower(t.Location)
	if loc == "body" || loc == "json" || loc == "form" {
		return true, ""
	}
	return false, "no XML-capable body or file carrier detected"
}

func alwaysReady(ScanTarget) (bool, string) { return true, "" }

func csrfReady(t ScanTarget) (bool, string) {
	return methodIn("POST", "PUT", "PATCH", "DELETE")(t)
}

func methodIn(methods ...string) func(ScanTarget) (bool, string) {
	allowed := map[string]struct{}{}
	for _, method := range methods {
		allowed[strings.ToUpper(method)] = struct{}{}
	}
	return func(t ScanTarget) (bool, string) {
		method := strings.ToUpper(strings.TrimSpace(t.Method))
		if method == "" {
			method = "GET"
		}
		if _, ok := allowed[method]; ok {
			return true, ""
		}
		return false, "method mismatch"
	}
}

func stateChangingOrBody(t ScanTarget) (bool, string) {
	switch strings.ToUpper(t.Method) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true, ""
	}
	if t.Profile.ContentType != "" || strings.EqualFold(t.Location, "json") ||
		strings.EqualFold(t.Location, "form") || strings.EqualFold(t.Parameter, "body") ||
		strings.TrimSpace(t.Parameter) != "" {
		return true, ""
	}
	return false, "not state-changing or body-capable"
}

func wordpressReady(t ScanTarget) (bool, string) {
	lower := strings.ToLower(t.EndpointURL)
	if strings.Contains(lower, "wp-") || strings.Contains(lower, "wordpress") {
		return true, ""
	}
	return false, "not wordpress surface"
}

func hasStoredMarker(t ScanTarget) (bool, string) {
	return false, "no stored markers yet"
}

func stringsContains(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

func stringsToLower(s string) string {
	return strings.ToLower(s)
}

func (r *Runner) shouldRunModule(name string, target ScanTarget) (bool, string) {
	if !r.cfg.AllowsModule(name) {
		return false, "disabled by scan config"
	}
	loc := strings.ToLower(strings.TrimSpace(target.Location))
	if loc == "" {
		loc = strings.ToLower(strings.TrimSpace(target.Profile.ParameterLocation))
	}
	// These checks currently produce useful leads, but they do not yet have a
	// deterministic, class-specific automatic proof contract. Keep them out of
	// the automatic finding pipeline until that contract exists.
	switch name {
	}
	if name == "second_order" {
		r.storedMu.Lock()
		_, ok := r.stored[target.EndpointURL+"::"+target.Parameter]
		storedLen := len(r.stored)
		r.storedMu.Unlock()
		if ok {
			return true, ""
		}
		if storedLen > 0 {
			return true, ""
		}
		return false, "no stored injection markers"
	}
	if name == "ssrf" {
		if r.cfg.FullModuleCoverage() || r.cfg.EnableOAST {
			return hasParameter(target)
		}
		if ok, _ := ssrfReady(target); ok {
			return true, ""
		}
		return false, "no server-side fetch semantics detected"
	}
	if name == "xxe" {
		if r.cfg.FullModuleCoverage() {
			return hasParameter(target)
		}
		if ok, _ := xxeReady(target); ok {
			return true, ""
		}
		return false, "no XML-capable body or file carrier detected"
	}
	if isCoreInjectionModule(name) && loc != "header" && strings.TrimSpace(target.Parameter) == "" {
		return false, "no parameter on target"
	}
	if r.cfg.FullModuleCoverage() && isCoreInjectionModule(name) {
		return hasParameter(target)
	}
	for _, reg := range [][]ModuleDescriptor{GroupARegistry, GroupBRegistry, GroupCRegistry, GroupDRegistry} {
		for _, m := range reg {
			if m.Manifest.Name == name {
				return m.Precondition(target)
			}
		}
	}
	return true, ""
}

func hasParameter(t ScanTarget) (bool, string) {
	if strings.TrimSpace(t.Parameter) != "" {
		return true, ""
	}
	return false, "no parameter"
}

func isCoreInjectionModule(name string) bool {
	switch name {
	case "sqli", "nosql", "ssti", "command_injection", "lfi", "idor",
		"open_redirect", "hpp", "prototype_pollution", "ldap_xpath_injection",
		"xss", "blind_xss":
		return true
	default:
		return false
	}
}

func isCriticalOrHighModule(name string) bool {
	switch name {
	case "sqli", "nosql", "ssti", "command_injection", "ssrf", "xxe", "lfi", "idor",
		"host_header", "file_upload", "bfla", "broken_auth", "jwt", "oauth", "smuggling":
		return true
	default:
		return false
	}
}

func (r *Runner) emitSkip(module string, target ScanTarget, reason string) {
	if r.emit != nil {
		_ = r.emit("plugin_skipped", reason, map[string]interface{}{
			"module": module, "endpoint": target.EndpointURL, "parameter": target.Parameter, "reason": reason,
		})
	}
}
