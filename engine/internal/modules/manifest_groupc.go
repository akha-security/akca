package modules

import "github.com/akha-security/akca/engine/internal/models"

var GroupCRegistry = []ModuleDescriptor{
	{
		Manifest:     models.PluginManifest{Name: "cors", Description: "CORS misconfiguration detection", Version: "0.1.0"},
		Precondition: endpointTypes("api", "html"),
	},
	{
		Manifest:     models.PluginManifest{Name: "jwt", Description: "JWT misconfiguration detection", Version: "0.1.0"},
		Precondition: pathContains("auth", "login", "token", "api"),
	},
	{
		Manifest:     models.PluginManifest{Name: "oauth", Description: "OAuth/OIDC/SSO misconfiguration", Version: "0.1.0"},
		Precondition: pathContains("oauth", "authorize", "callback", "sso", "oidc"),
	},
	{
		Manifest:     models.PluginManifest{Name: "cache_poisoning", Description: "Web cache poisoning via unkeyed inputs", Version: "0.1.0"},
		Precondition: alwaysReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "cache_deception", Description: "Web cache deception via path confusion", Version: "0.1.0"},
		Precondition: alwaysReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "mass_assignment", Description: "Mass assignment and hidden field binding", Version: "0.1.0"},
		Precondition: contentTypes("json", "api"),
	},
	{
		Manifest:     models.PluginManifest{Name: "api_exposure", Description: "API excessive data exposure", Version: "0.1.0"},
		Precondition: endpointTypes("api", "graphql"),
	},
	{
		Manifest:     models.PluginManifest{Name: "rate_limit", Description: "Rate limit weakness detection", Version: "0.1.0"},
		Precondition: pathContains("login", "auth", "api", "token"),
	},
	{
		Manifest:     models.PluginManifest{Name: "account_enum", Description: "Account enumeration signals", Version: "0.1.0"},
		Precondition: pathContains("login", "register", "reset", "forgot", "signup"),
	},
	{
		Manifest:     models.PluginManifest{Name: "hpp", Description: "HTTP parameter pollution testing", Version: "0.1.0"},
		Precondition: alwaysReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "broken_auth", Description: "Broken authentication checks", Version: "0.1.0"},
		Precondition: pathContains("login", "auth", "oauth", "admin", "session", "account"),
	},
	{
		Manifest:     models.PluginManifest{Name: "csrf", Description: "Missing CSRF protection on state-changing endpoints", Version: "0.1.0"},
		Precondition: csrfReady,
	},
	{
		Manifest:     models.PluginManifest{Name: "wordpress_fuzz", Description: "WordPress-specific exposure probes", Version: "0.1.0"},
		Precondition: wordpressReady,
	},
}
