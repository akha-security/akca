package modules

import "github.com/akha-security/akca/engine/internal/models"

var GroupARegistry = []ModuleDescriptor{
	{
		Manifest:     models.PluginManifest{Name: "ssti", Description: "Server-side template injection", Version: "0.1.0"},
		Precondition: sstiReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "blind_xss", Description: "Blind XSS via OAST callback correlation", Version: "0.1.0"},
		Precondition: contentTypes("html", "javascript", "json"),
	},
}

func sstiReady(t ScanTarget) (bool, string) {
	if ok, _ := paramLike("template", "view", "layout", "format", "message", "subject", "body", "preview", "render")(t); ok {
		return true, ""
	}
	if t.Payloads.Tech.Framework != "" || t.Payloads.Tech.BackendLanguage != "" {
		return true, ""
	}
	if t.Profile.Confidence >= 0.5 && t.Profile.ReflectionKind != "" &&
		t.Profile.ReflectionKind != "removed" {
		return true, ""
	}
	return false, "no template/evaluator surface evidence"
}
