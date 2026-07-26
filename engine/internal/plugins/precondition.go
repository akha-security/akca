package plugins

import (
	"strings"

	"github.com/akha-security/akca/engine/internal/models"
)

type Precondition struct {
	RequiredEndpointTypes []string
	RequireAuthSurface    bool
	RequireStateChanging  bool
	RequireContentTypes   []string
	BlockedWAFVendors     []string
	RequireTechHints      []string
}

type Module struct {
	Manifest     models.PluginManifest
	Precondition Precondition
}

var registry = []Module{
	{
		Manifest: models.PluginManifest{Name: "xss", Description: "Cross-site scripting", Version: "0.1.0"},
		Precondition: Precondition{
			RequiredEndpointTypes: []string{"html", "api"},
			RequireContentTypes:   []string{"text/html", "application/json"},
		},
	},
	{
		Manifest: models.PluginManifest{Name: "sqli", Description: "SQL injection", Version: "0.1.0"},
		Precondition: Precondition{
			RequiredEndpointTypes: []string{"api", "html", "graphql"},
		},
	},
	{
		Manifest: models.PluginManifest{Name: "nosql", Description: "NoSQL injection (MongoDB operators)", Version: "0.1.0"},
		Precondition: Precondition{
			RequiredEndpointTypes: []string{"api", "graphql"},
			RequireContentTypes:   []string{"application/json"},
		},
	},
	{
		Manifest: models.PluginManifest{Name: "ssrf", Description: "Server-side request forgery", Version: "0.1.0"},
		Precondition: Precondition{
			RequiredEndpointTypes: []string{"api", "graphql"},
		},
	},
	{
		Manifest: models.PluginManifest{Name: "graphql", Description: "GraphQL testing", Version: "0.1.0"},
		Precondition: Precondition{
			RequiredEndpointTypes: []string{"graphql"},
		},
	},
	{
		Manifest: models.PluginManifest{Name: "broken_auth", Description: "Broken authentication", Version: "0.1.0"},
		Precondition: Precondition{
			RequireAuthSurface: true,
		},
	},
	{
		Manifest: models.PluginManifest{Name: "idor", Description: "Insecure direct object reference", Version: "0.1.0"},
		Precondition: Precondition{
			RequireAuthSurface:    true,
			RequiredEndpointTypes: []string{"api", "graphql"},
		},
	},
	{
		Manifest: models.PluginManifest{Name: "command_injection", Description: "OS command injection", Version: "0.1.0"},
		Precondition: Precondition{
			RequiredEndpointTypes: []string{"api", "html"},
		},
	},
	{
		Manifest: models.PluginManifest{Name: "ssti", Description: "Server-side template injection", Version: "0.1.0"},
		Precondition: Precondition{
			RequireTechHints: []string{"framework:Laravel", "framework:Django", "framework:Rails", "framework:Spring"},
		},
	},
}

func Registry() []Module {
	out := make([]Module, len(registry))
	copy(out, registry)
	return out
}

func EvaluatePreconditions(intel models.EndpointIntelligence) (ready []string, skipped []models.SkipReason) {
	for _, mod := range registry {
		if ok, reason := checkPrecondition(mod, intel); ok {
			ready = append(ready, mod.Manifest.Name)
		} else {
			skipped = append(skipped, models.SkipReason{
				Module:   mod.Manifest.Name,
				Reason:   reason,
				Endpoint: intel.URL,
			})
		}
	}
	return ready, skipped
}

func checkPrecondition(mod Module, intel models.EndpointIntelligence) (bool, string) {
	p := mod.Precondition
	if len(p.RequiredEndpointTypes) > 0 && !containsFold(p.RequiredEndpointTypes, intel.EndpointType) {
		return false, "endpoint type mismatch"
	}
	if p.RequireAuthSurface && !intel.AuthRequired {
		return false, "auth surface not detected"
	}
	if p.RequireStateChanging && !intel.StateChanging {
		return false, "endpoint is not state-changing"
	}
	if len(p.RequireContentTypes) > 0 && !contentTypeMatches(p.RequireContentTypes, intel.ContentType) {
		return false, "content type mismatch"
	}
	if intel.WAFProfile != nil && len(p.BlockedWAFVendors) > 0 && containsFold(p.BlockedWAFVendors, intel.WAFProfile.Vendor) {
		return false, "blocked by WAF vendor policy"
	}
	if len(p.RequireTechHints) > 0 && intel.TechFingerprint != nil {
		hints := intel.TechFingerprint.Hints
		matched := false
		for _, required := range p.RequireTechHints {
			for _, hint := range hints {
				if strings.EqualFold(hint, required) {
					matched = true
					break
				}
			}
		}
		if !matched {
			return false, "required tech hint not found"
		}
	}
	return true, ""
}

func containsFold(items []string, value string) bool {
	for _, item := range items {
		if strings.EqualFold(item, value) {
			return true
		}
	}
	return false
}

func contentTypeMatches(allowed []string, contentType string) bool {
	ct := strings.ToLower(contentType)
	for _, a := range allowed {
		if strings.Contains(ct, strings.ToLower(a)) {
			return true
		}
	}
	return contentType == ""
}
