package modules

import "github.com/akha-security/akca/engine/internal/models"

var GroupDRegistry = []ModuleDescriptor{
	{Manifest: models.PluginManifest{Name: "security_headers", Description: "Missing or weak security headers", Version: "0.1.0"}, Precondition: alwaysReady},
	{Manifest: models.PluginManifest{Name: "tls_misconfig", Description: "TLS protocol and cipher misconfiguration", Version: "0.1.0"}, Precondition: alwaysReady},
	{Manifest: models.PluginManifest{Name: "vulnerable_components", Description: "Technology and component version inventory", Version: "0.1.0"}, Precondition: alwaysReady},
	{Manifest: models.PluginManifest{Name: "sensitive_data", Description: "Sensitive data exposure in responses", Version: "0.1.0"}, Precondition: alwaysReady},
	{Manifest: models.PluginManifest{Name: "secret_exposure", Description: "Secret and credential exposure", Version: "0.1.0"}, Precondition: alwaysReady},
	{Manifest: models.PluginManifest{Name: "cicd_exposure", Description: "Exposed CI/CD and build artifacts", Version: "0.1.0"}, Precondition: pathContains(".git", "jenkins", "gitlab", "github", "actions", "pipeline")},
	{Manifest: models.PluginManifest{Name: "git_recovery", Description: "Partial .git repository recovery and object enumeration", Version: "0.1.0"}, Precondition: alwaysReady},
	{Manifest: models.PluginManifest{Name: "source_code_disclosure", Description: "Backup/source file disclosure and semantic code analysis", Version: "0.1.0"}, Precondition: alwaysReady},
	{Manifest: models.PluginManifest{Name: "graphql", Description: "GraphQL introspection and schema analysis", Version: "0.1.0"}, Precondition: endpointTypes("graphql", "api")},
	{Manifest: models.PluginManifest{Name: "script_source", Description: "Third-party script source and broken CDN link analysis", Version: "0.1.0"}, Precondition: contentTypes("html", "javascript")},
	{Manifest: models.PluginManifest{Name: "websocket", Description: "WebSocket SQLi/XSS/IDOR deep testing", Version: "0.1.0"}, Precondition: pathContains("ws", "socket", "realtime", "stream")},
	{Manifest: models.PluginManifest{Name: "cloud_storage", Description: "Cloud storage bucket exposure", Version: "0.1.0"}, Precondition: alwaysReady},
	{Manifest: models.PluginManifest{Name: "cloud_posture", Description: "Cloud auth provider abuse and terraform state exposure", Version: "0.1.0"}, Precondition: alwaysReady},
	{Manifest: models.PluginManifest{Name: "client_ssti", Description: "Client-side template injection", Version: "0.1.0"}, Precondition: contentTypes("html", "javascript")},
	{Manifest: models.PluginManifest{Name: "smuggling", Description: "HTTP request smuggling signals", Version: "0.1.0"}, Precondition: stateChangingOrBody},
	{Manifest: models.PluginManifest{Name: "prototype_pollution", Description: "Prototype pollution detection", Version: "0.1.0"}, Precondition: contentTypes("json", "javascript")},
	{Manifest: models.PluginManifest{Name: "ldap_xpath_injection", Description: "LDAP/XPath/header injection signals", Version: "0.1.0"}, Precondition: alwaysReady},
	{Manifest: models.PluginManifest{Name: "debug_admin", Description: "Debug and admin interface exposure", Version: "0.1.0"}, Precondition: pathContains("debug", "admin", "actuator", "console", "trace")},
	{Manifest: models.PluginManifest{Name: "business_logic", Description: "Business logic testing signals", Version: "0.1.0"}, Precondition: pathContains("cart", "checkout", "order", "payment", "coupon")},
	{Manifest: models.PluginManifest{Name: "race_condition", Description: "Race condition detection", Version: "0.1.0"}, Precondition: pathContains("redeem", "transfer", "vote", "claim", "coupon")},
	{Manifest: models.PluginManifest{Name: "api_versioning", Description: "API versioning discovery", Version: "0.1.0"}, Precondition: endpointTypes("api", "graphql")},
	{Manifest: models.PluginManifest{Name: "known_cve", Description: "Known CVE detection from embedded snapshot", Version: "0.1.0"}, Precondition: alwaysReady},
}
