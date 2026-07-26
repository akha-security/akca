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
		Precondition: contentTypes("xml", "soap", "json"),
	},
	{
		Manifest:     models.PluginManifest{Name: "lfi", Description: "Local/remote file inclusion and path traversal", Version: "0.1.0"},
		Precondition: alwaysReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "file_upload", Description: "File upload risk detection", Version: "0.1.0"},
		Precondition: pathContains("upload", "import", "attachment"),
	},
	{
		Manifest:     models.PluginManifest{Name: "idor", Description: "Insecure direct object reference / BOLA", Version: "0.1.0"},
		Precondition: paramLike("id", "user", "account", "uuid"),
	},
	{
		Manifest:     models.PluginManifest{Name: "bfla", Description: "Broken function-level authorization", Version: "0.1.0"},
		Precondition: pathContains("admin", "manage", "internal"),
	},
	{
		Manifest:     models.PluginManifest{Name: "open_redirect", Description: "Open redirect detection", Version: "0.1.0"},
		Precondition: paramLike("url", "redirect", "next", "return", "dest"),
	},
	{
		Manifest:     models.PluginManifest{Name: "host_header", Description: "Host header injection", Version: "0.1.0"},
		Precondition: alwaysReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "second_order", Description: "Second-order injection tracking", Version: "0.1.0"},
		Precondition: hasStoredMarker,
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

func ssrfReady(t ScanTarget) (bool, string) {
	if ok, _ := paramLike(
		"url", "uri", "link", "src", "source", "target", "dest", "redirect",
		"callback", "webhook", "feed", "image", "avatar", "proxy", "endpoint",
		"host", "domain", "fetch", "remote", "resource", "load", "preview",
		"href", "address", "server", "site", "return", "next", "continue",
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
		strings.EqualFold(t.Location, "form") || strings.EqualFold(t.Parameter, "body") {
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
		if ok, reason := ssrfReady(target); ok {
			return true, ""
		} else if r.cfg.FullModuleCoverage() && r.cfg.EnableOAST {
			if has, _ := hasParameter(target); has {
				// On a weakly named but real parameter, full coverage sends
				// only a harmless external callback token. Direct cloud
				// metadata/internal-address probes remain restricted to
				// strong fetch candidates inside runSSRF.
				return true, ""
			}
			return false, reason
		} else {
			return false, reason
		}
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
	case "ssrf", "xxe", "lfi", "idor", "open_redirect", "host_header", "file_upload", "bfla":
		return true
	default:
		return false
	}
}

func (r *Runner) emitSkip(module string, target ScanTarget, reason string) {
	_ = r.emit("plugin_skipped", reason, map[string]interface{}{
		"module": module, "endpoint": target.EndpointURL, "parameter": target.Parameter, "reason": reason,
	})
}
