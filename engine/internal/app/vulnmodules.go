package app

import (
	"context"
	"errors"
	"time"

	"github.com/akha-security/akca/engine/internal/modules"
)

type vulnModulePhase struct {
	name     string
	title    string
	usesOAST bool
}

var fullScanModuleOrder = []vulnModulePhase{
	// 1. Passive & Metadata Analysis (Crawled responses, headers, DOM/JS)
	{name: "security_headers", title: "Security headers scanning"},
	{name: "cookie_security", title: "Cookie and session security scanning"},
	{name: "tls_misconfig", title: "TLS misconfiguration scanning"},
	{name: "sensitive_data", title: "Sensitive data scanning"},
	{name: "secret_exposure", title: "Secret exposure scanning"},
	{name: "vulnerable_components", title: "Vulnerable components scanning"},
	{name: "known_cve", title: "Known CVE scanning"},
	{name: "script_source", title: "Script source scanning"},

	// 2. Lightweight Active & Exposure Probing
	{name: "debug_admin", title: "Debug/admin exposure scanning"},
	{name: "actuator", title: "Spring actuator scanning"},
	{name: "devops_exposure", title: "DevOps exposure scanning"},
	{name: "cicd_exposure", title: "CI/CD exposure scanning"},
	{name: "git_recovery", title: "Git recovery scanning"},
	{name: "source_code_disclosure", title: "Source code disclosure scanning"},
	{name: "backup_archives", title: "Backup archive scanning"},
	{name: "cloud_storage", title: "Cloud storage scanning"},
	{name: "cloud_takeover", title: "Cloud takeover scanning"},
	{name: "cloud_posture", title: "Cloud posture scanning"},
	{name: "http_methods", title: "HTTP methods scanning"},
	{name: "cors", title: "CORS scanning", usesOAST: true},
	{name: "api_versioning", title: "API versioning scanning"},
	{name: "api_exposure", title: "API exposure scanning"},
	{name: "wordpress_fuzz", title: "WordPress exposure scanning"},
	{name: "nginx_alias", title: "Nginx alias traversal scanning"},
	{name: "nextjs_bypass", title: "Next.js middleware & SSRF scanning", usesOAST: true},
	{name: "framework_debug", title: "Framework debug & devtools exposure scanning"},
	{name: "iis_discovery", title: "IIS shortname & extension confusion scanning"},
	{name: "firebase_misconfig", title: "Firebase RTDB & storage misconfiguration scanning"},
	{name: "spring_cloud_jolokia", title: "Spring Cloud Config & Jolokia exposure scanning"},
	{name: "saas_exposure", title: "ServiceNow & Salesforce exposure scanning"},
	{name: "cpdos", title: "Cache-poisoned denial of service scanning"},
	{name: "proxy_path_confusion", title: "Reverse proxy path confusion scanning"},
	{name: "ws_cswsh", title: "Cross-site WebSocket hijacking scanning"},
	{name: "pdf_injection", title: "PDF generation SSRF & injection scanning", usesOAST: true},
	{name: "jsonp_callback", title: "JSONP callback & XSSI scanning"},
	{name: "react_rsc_rce", title: "React Server Components RCE scanning"},
	{name: "server_side_js_injection", title: "Server-side JavaScript (Node.js) scanning", usesOAST: true},
	{name: "csti_detection", title: "Client-side template injection scanning"},
	{name: "swagger_exposure", title: "Swagger & OpenAPI specification scanning"},
	{name: "sensitive_file_discovery", title: "Sensitive file & configuration scanning"},
	{name: "http_smuggling", title: "HTTP Request Smuggling scanning"},
	{name: "race_condition_sync", title: "Synchronized race condition scanning"},
	{name: "oauth_flow_audit", title: "OAuth & OIDC flow security auditing"},
	{name: "cloud_native_exposure", title: "Cloud native & container API exposure scanning"},
	{name: "grpc_scan", title: "gRPC & gRPC-Web protocol security scanning"},

	// 3. Authentication, Authorization & Logic
	{name: "route_auth_bypass", title: "Route authentication bypass scanning"},
	{name: "broken_auth", title: "Broken authentication scanning"},
	{name: "improper_auth", title: "Improper authentication scanning"},
	{name: "account_recovery", title: "Account recovery scanning"},
	{name: "jwt", title: "JWT scanning"},
	{name: "oauth", title: "OAuth scanning"},
	{name: "tenant_isolation", title: "Tenant isolation scanning"},
	{name: "webhook_security", title: "Webhook security scanning"},
	{name: "parser_differential", title: "Parser differential scanning"},
	{name: "idor", title: "IDOR scanning"},
	{name: "bfla", title: "BFLA scanning"},
	{name: "csrf", title: "CSRF scanning"},
	{name: "mass_assignment", title: "Mass assignment scanning"},
	{name: "rate_limit", title: "Rate limit scanning"},
	{name: "account_enum", title: "Account enumeration scanning"},

	// 4. Client-side & Target Protocol Probes
	{name: "open_redirect", title: "Open redirect scanning"},
	{name: "client_ssti", title: "Client-side SSTI scanning"},
	{name: "prototype_pollution", title: "Prototype pollution scanning"},
	{name: "hpp", title: "HTTP parameter pollution scanning"},
	{name: "crlf", title: "CRLF injection scanning"},
	{name: "host_header", title: "Host header scanning"},
	{name: "host_poisoning", title: "Host poisoning scanning"},
	{name: "graphql", title: "GraphQL scanning"},
	{name: "websocket", title: "WebSocket scanning"},

	// 5. Heavy Active Injection & Fuzzing (High WAF/rate-limit risk)
	{name: "xss", title: "XSS scanning"},
	{name: "blind_xss", title: "Blind XSS OAST scanning", usesOAST: true},
	{name: "sqli", title: "SQL injection scanning", usesOAST: true},
	{name: "nosql", title: "NoSQL injection scanning"},
	{name: "ssti", title: "SSTI scanning"},
	{name: "command_injection", title: "RCE / command injection scanning", usesOAST: true},
	{name: "ssrf", title: "SSRF scanning", usesOAST: true},
	{name: "xxe", title: "XXE scanning", usesOAST: true},
	{name: "lfi", title: "LFI / RFI scanning", usesOAST: true},
	{name: "file_upload", title: "File upload scanning"},
	{name: "ldap", title: "LDAP injection scanning"},
	{name: "xpath", title: "XPath injection scanning"},
	{name: "ldap_xpath_injection", title: "LDAP/XPath composite scanning"},
	{name: "insecure_deserialization", title: "Insecure deserialization scanning"},
	{name: "business_logic", title: "Business logic scanning"},
	{name: "race_condition", title: "Race condition scanning"},
	{name: "second_order", title: "Second-order scanning"},
	{name: "cache_poisoning", title: "Cache poisoning scanning"},
	{name: "cache_deception", title: "Cache deception scanning"},
	{name: "smuggling", title: "HTTP request smuggling scanning"},
	{name: "llm_injection", title: "AI/LLM prompt injection scanning", usesOAST: true},

	// Destructive to the scanner's own authenticated session; always run last.
	{name: "session_lifecycle", title: "Session lifecycle scanning"},
}

func (e *Engine) vulnModuleRunner() *modules.Runner {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.moduleRunner != nil {
		return e.moduleRunner
	}
	var oastClient modules.OASTClient
	if e.oast != nil {
		oastClient = e.oast
	}
	e.moduleRunner = modules.NewRunner(e.session.ID, e.client, e.scope, e.db, e.verifier, oastClient, e.Emit, e.session.Config, e.moduleRunnerOpts()...)
	return e.moduleRunner
}

func (e *Engine) runVulnModulesSequential(ctx context.Context) error {
	runner := e.vulnModuleRunner()
	hasError := false
	for moduleOffset, item := range fullScanModuleOrder {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !e.session.Config.AllowsModule(item.name) {
			continue
		}
		phase := "vuln_module_" + item.name
		e.session.SetPhase(phase)
		moduleIndex := moduleOffset + 1
		moduleTotal := len(fullScanModuleOrder)
		_ = e.Emit("phase_started", item.title, map[string]interface{}{
			"phase": phase, "module": item.name, "module_index": moduleIndex, "module_total": moduleTotal,
		})
		findings, err := runner.RunModuleFromDB(ctx, item.name, e.moduleTargetLimit())
		if err != nil {
			hasError = true
			_ = e.Emit("scan_error", err.Error(), map[string]interface{}{"phase": phase, "module": item.name})
		}
		_ = e.Emit("phase_finished", item.title, map[string]interface{}{
			"phase": phase, "module": item.name, "findings": len(findings),
			"module_index": moduleIndex, "module_total": moduleTotal,
		})
		if item.usesOAST {
			e.runOASTModuleDrain(ctx, item.name)
		}
	}
	if hasError {
		return errors.New("one or more vulnerability modules failed")
	}
	return nil
}

func (e *Engine) runOASTModuleDrain(ctx context.Context, module string) {
	if !e.session.Config.EnableOAST || e.oast == nil || e.db == nil {
		return
	}
	if e.oast.CorrelationCount() == 0 {
		return
	}
	totalDrain := e.session.Config.OASTDrainDuration()
	if totalDrain <= 0 {
		return
	}
	duration := e.session.Config.OASTPollInterval * 2
	if duration <= 0 {
		duration = 4 * time.Second
	}
	if duration < 3*time.Second {
		duration = 3 * time.Second
	}
	if duration > 8*time.Second {
		duration = 8 * time.Second
	}
	if totalDrain < duration {
		duration = totalDrain
	}
	before, _ := e.db.CountOASTCallbacks(e.session.ID)
	_ = e.Emit("oast_module_drain_started", "module OAST callback drain", map[string]interface{}{
		"scan_id": e.session.ID, "module": module, "duration_sec": int(duration.Seconds()), "pending_correlations": e.oast.CorrelationCount(),
	})
	e.oast.Drain(ctx, duration)
	after, _ := e.db.CountOASTCallbacks(e.session.ID)
	newCallbacks := after - before
	if newCallbacks < 0 {
		newCallbacks = 0
	}
	if _, err := modules.FinalizeOASTFindings(e.db, e.session.ID, e.Emit); err != nil {
		_ = e.Emit("scan_error", err.Error(), map[string]interface{}{"phase": "oast_module_drain", "module": module})
	}
	_ = e.Emit("oast_module_drain_finished", "module OAST callback drain complete", map[string]interface{}{
		"scan_id": e.session.ID, "module": module, "callbacks_received": newCallbacks, "total_callbacks": after,
	})
}

func (e *Engine) runVulnModulesPhaseA(ctx context.Context) error {
	e.session.SetPhase("vuln_modules_a")
	_ = e.Emit("phase_started", "Injection vulnerability scanning", map[string]interface{}{"phase": "vuln_modules_a"})

	runner := e.vulnModuleRunner()
	findings, err := runner.RunGroupAFromDB(ctx, e.moduleTargetLimit())
	if err != nil {
		return err
	}
	_ = e.Emit("phase_finished", "Injection vulnerability scanning", map[string]interface{}{
		"phase": "vuln_modules_a", "findings": len(findings),
	})
	return nil
}

func (e *Engine) runVulnModulesPhaseB(ctx context.Context) error {
	e.session.SetPhase("vuln_modules_b")
	_ = e.Emit("phase_started", "SSRF, LFI & XXE scanning", map[string]interface{}{"phase": "vuln_modules_b"})

	runner := e.vulnModuleRunner()
	findings, err := runner.RunGroupBFromDB(ctx, e.moduleTargetLimit())
	if err != nil {
		return err
	}
	_ = e.Emit("phase_finished", "SSRF, LFI & XXE scanning", map[string]interface{}{
		"phase": "vuln_modules_b", "findings": len(findings),
	})
	return nil
}

func (e *Engine) runVulnModulesPhaseC(ctx context.Context) error {
	e.session.SetPhase("vuln_modules_c")
	_ = e.Emit("phase_started", "Authentication & API security scanning", map[string]interface{}{"phase": "vuln_modules_c"})

	runner := e.vulnModuleRunner()
	findings, err := runner.RunGroupCFromDB(ctx, e.moduleTargetLimit())
	if err != nil {
		return err
	}
	_ = e.Emit("phase_finished", "Authentication & API security scanning", map[string]interface{}{
		"phase": "vuln_modules_c", "findings": len(findings),
	})
	return nil
}

func (e *Engine) runVulnModulesPhaseD(ctx context.Context) error {
	e.session.SetPhase("vuln_modules_d")
	_ = e.Emit("phase_started", "Configuration & exposure scanning", map[string]interface{}{"phase": "vuln_modules_d"})

	runner := e.vulnModuleRunner()
	findings, err := runner.RunGroupDFromDB(ctx, e.moduleTargetLimit())
	if err != nil {
		return err
	}
	_ = e.Emit("phase_finished", "Configuration & exposure scanning", map[string]interface{}{
		"phase": "vuln_modules_d", "findings": len(findings),
	})
	return nil
}
