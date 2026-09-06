package modules

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
)

func (r *Runner) RunModuleFromDB(ctx context.Context, module string, limit int) ([]ModuleFinding, error) {
	targets, err := r.LoadTargetsWithEndpointsFromDB(limit)
	if err != nil {
		return nil, err
	}
	return r.RunModule(ctx, module, targets)
}

func (r *Runner) RunModule(ctx context.Context, module string, targets []ScanTarget) ([]ModuleFinding, error) {
	if !r.cfg.AllowsModule(module) {
		return nil, nil
	}
	_ = r.emit("vuln_module_started", module+" scanning started", map[string]interface{}{
		"scan_id": r.scanID, "module": module, "targets": len(targets),
	})

	workers := r.cfg.PerHostConcurrency
	if workers <= 0 {
		workers = 8
	}
	if workers > len(targets) {
		workers = len(targets)
	}

	var mu sync.Mutex
	var findings []ModuleFinding
	var testedCount atomic.Int64
	var skippedBudgetCount atomic.Int64
	errorsBefore := r.executionErrors.Load()
	targetCh := make(chan ScanTarget, moduleQueueCapacity(workers, len(targets)))

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if rec := recover(); rec != nil {
					r.executionErrors.Add(1)
					_ = r.emit("log", fmt.Sprintf("RunModule(%s) worker recovered from panic: %v", module, rec), map[string]interface{}{"scan_id": r.scanID})
				}
			}()
			for target := range targetCh {
				if ctx.Err() != nil {
					return
				}
				if r.budgetExhausted.Load() || !r.canModuleProbe(module) {
					skippedBudgetCount.Add(1)
					continue
				}
				if !r.scope.IsInScope(target.EndpointURL) {
					continue
				}
				testedCount.Add(1)
				func() {
					defer func() {
						if rec := recover(); rec != nil {
							r.executionErrors.Add(1)
							_ = r.emit("log", fmt.Sprintf("RunModule(%s) target %s recovered from panic: %v", module, target.EndpointURL, rec), map[string]interface{}{"scan_id": r.scanID})
						}
					}()
					localFindings := r.runSingleModule(ctx, module, target)
					if len(localFindings) > 0 {
						mu.Lock()
						findings = append(findings, localFindings...)
						mu.Unlock()
					}
				}()
			}
		}()
	}
	feedModuleTargets(ctx, targetCh, targets)
	wg.Wait()

	if module == "sqli" || module == "command_injection" {
		findings = append(findings, r.flushDelayedTimingVerifications(ctx)...)
	}
	totalTargets := len(targets)
	tested := int(testedCount.Load())
	skipped := int(skippedBudgetCount.Load())
	coveragePct := 100.0
	if totalTargets > 0 {
		coveragePct = float64(tested) / float64(totalTargets) * 100.0
	}
	_ = r.emit("vuln_module_finished", module+" scanning finished", map[string]interface{}{
		"scan_id": r.scanID, "module": module, "findings": len(findings),
		"targets_tested": tested, "targets_total": totalTargets,
		"coverage_percentage": fmt.Sprintf("%.1f%%", coveragePct),
	})
	if skipped > 0 {
		r.emitOnce("module_budget_starved:"+module, "coverage_gap",
			fmt.Sprintf("Module %s was budget-starved: tested %d of %d targets (%.1f%% coverage)", module, tested, totalTargets, coveragePct),
			map[string]interface{}{
				"scan_id": r.scanID, "module": module,
				"targets_tested": tested, "targets_total": totalTargets,
				"coverage_pct": coveragePct,
			},
		)
	}
	if failed := r.executionErrors.Load() - errorsBefore; failed > 0 {
		return findings, fmt.Errorf("module %s completed with %d execution or persistence errors", module, failed)
	}
	return findings, nil
}

func (r *Runner) runSingleModule(ctx context.Context, module string, target ScanTarget) []ModuleFinding {
	switch module {
	case "xss":
		return r.runXSS(ctx, target)
	case "blind_xss":
		return r.runBlindXSS(ctx, target)
	case "sqli":
		return r.runSQLi(ctx, target)
	case "nosql":
		return r.runNoSQLi(ctx, target)
	case "ssti":
		return r.runSSTI(ctx, target)
	case "command_injection":
		return r.runCommandInjection(ctx, target)
	case "ssrf":
		return r.runSSRF(ctx, target)
	case "xxe":
		return r.runXXE(ctx, target)
	case "lfi":
		return r.runLFI(ctx, target)
	case "file_upload":
		return r.runFileUpload(ctx, target)
	case "idor":
		return r.runIDOR(ctx, target)
	case "bfla":
		return r.runBFLA(ctx, target)
	case "open_redirect":
		return r.runOpenRedirect(ctx, target)
	case "host_header":
		return r.runHostHeader(ctx, target)
	case "second_order":
		return r.runSecondOrder(ctx, target)
	case "cors":
		if !r.endpointModuleOnce("cors", target) {
			return nil
		}
		return r.runCORS(ctx, target)
	case "jwt":
		return r.runJWT(ctx, target)
	case "oauth":
		return r.runOAuth(ctx, target)
	case "cache_poisoning":
		return r.runCachePoisoning(ctx, target)
	case "cache_deception":
		return r.runCacheDeception(ctx, target)
	case "mass_assignment":
		if !r.endpointModuleOnce("mass_assignment", target) {
			return nil
		}
		return r.runMassAssignment(ctx, target)
	case "api_exposure":
		return r.runAPIExposure(ctx, target)
	case "rate_limit":
		return r.runRateLimit(ctx, target)
	case "account_enum":
		return r.runAccountEnum(ctx, target)
	case "hpp":
		return r.runHPP(ctx, target)
	case "broken_auth":
		if !r.endpointModuleOnce("broken_auth", target) {
			return nil
		}
		return r.runBrokenAuth(ctx, target)
	case "improper_auth":
		return r.runImproperAuthentication(ctx, target)
	case "csrf":
		return r.runCSRF(ctx, target)
	case "crlf":
		return r.runCRLF(ctx, target)
	case "xpath":
		return r.runXPathInjection(ctx, target)
	case "ldap":
		return r.runLDAPInjection(ctx, target)
	case "graphql":
		return r.runGraphQL(ctx, target)
	case "websocket":
		return r.runWebSocket(ctx, target)
	case "business_logic":
		return r.runBusinessLogic(ctx, target)
	case "race_condition":
		return r.runRaceCondition(ctx, target)
	case "smuggling":
		if !r.endpointModuleOnce("smuggling", target) {
			return nil
		}
		return r.runSmuggling(ctx, target)
	case "security_headers":
		return r.runSecurityHeaders(ctx, target)
	case "cookie_security":
		return r.runCookieSecurity(ctx, target)
	case "tls_misconfig":
		if !r.endpointModuleOnce("tls_misconfig", target) {
			return nil
		}
		return r.runTLSMisconfig(ctx, target)
	case "vulnerable_components":
		return r.runVulnerableComponents(ctx, target)
	case "sensitive_data":
		return r.runSensitiveData(ctx, target)
	case "secret_exposure":
		if !r.contentModuleOnce("secret_exposure", target) {
			return nil
		}
		return r.runSecretExposure(ctx, target)
	case "cicd_exposure":
		if !r.endpointModuleOnce("cicd_exposure", target) {
			return nil
		}
		return r.runCICDExposure(ctx, target)
	case "git_recovery":
		if !r.endpointModuleOnce("git_recovery", target) {
			return nil
		}
		return r.runGitDeepRecovery(ctx, target)
	case "source_code_disclosure":
		if !r.endpointModuleOnce("source_code_disclosure", target) {
			return nil
		}
		return r.runSourceCodeDisclosure(ctx, target)
	case "script_source":
		return r.runScriptSource(ctx, target)
	case "cloud_storage":
		if !r.endpointModuleOnce("cloud_storage", target) {
			return nil
		}
		return r.runCloudStorage(ctx, target)
	case "cloud_posture":
		if !r.endpointModuleOnce("cloud_posture", target) {
			return nil
		}
		return r.runCloudPosture(ctx, target)
	case "client_ssti":
		return r.runClientSSTI(ctx, target)
	case "prototype_pollution":
		return r.runPrototypePollution(ctx, target)
	case "insecure_deserialization":
		return r.runInsecureDeserialization(ctx, target)
	case "ldap_xpath_injection":
		return r.runLDAPXPathInjection(ctx, target)
	case "debug_admin":
		if !r.endpointModuleOnce("debug_admin", target) {
			return nil
		}
		return r.runDebugAdmin(ctx, target)
	case "actuator":
		if !r.endpointModuleOnce("actuator", target) {
			return nil
		}
		return r.runSpringActuator(ctx, target)
	case "cloud_takeover":
		if !r.endpointModuleOnce("cloud_takeover", target) {
			return nil
		}
		return r.runCloudTakeover(ctx, target)
	case "api_versioning":
		return r.runAPIVersioning(ctx, target)
	case "known_cve":
		return r.runKnownCVE(ctx, target)
	case "http_methods":
		if !r.endpointModuleOnce("http_methods", target) {
			return nil
		}
		return r.runHTTPMethods(ctx, target)
	case "host_poisoning":
		if !r.endpointModuleOnce("host_poisoning", target) {
			return nil
		}
		return r.runHostPoisoning(ctx, target)
	case "devops_exposure":
		if !r.endpointModuleOnce("devops_exposure", target) {
			return nil
		}
		return r.runDevOpsExposure(ctx, target)
	case "backup_archives":
		if !r.endpointModuleOnce("backup_archives", target) {
			return nil
		}
		return r.runBackupArchives(ctx, target)
	case "wordpress_fuzz":
		if !r.endpointModuleOnce("wordpress_fuzz", target) {
			return nil
		}
		return r.runWordPressFuzz(ctx, target)
	case "llm_injection":
		return r.runLLMInjection(ctx, target)
	case "route_auth_bypass":
		if !r.endpointModuleOnce("route_auth_bypass", target) {
			return nil
		}
		return r.runRouteAuthBypass(ctx, target)
	case "tenant_isolation":
		return r.runTenantIsolation(ctx, target)
	case "account_recovery":
		if !r.endpointModuleOnce("account_recovery", target) {
			return nil
		}
		return r.runAccountRecovery(ctx, target)
	case "webhook_security":
		if !r.endpointModuleOnce("webhook_security", target) {
			return nil
		}
		return r.runWebhookSecurity(ctx, target)
	case "session_lifecycle":
		if !r.endpointModuleOnce("session_lifecycle", target) {
			return nil
		}
		return r.runSessionLifecycle(ctx, target)
	case "parser_differential":
		return r.runParserDifferential(ctx, target)
	case "nginx_alias":
		if !r.endpointModuleOnce("nginx_alias", target) {
			return nil
		}
		return r.runNginxAlias(ctx, target)
	case "nextjs_bypass":
		if !r.endpointModuleOnce("nextjs_bypass", target) {
			return nil
		}
		return r.runNextJSBypass(ctx, target)
	case "framework_debug":
		if !r.endpointModuleOnce("framework_debug", target) {
			return nil
		}
		return r.runFrameworkDebug(ctx, target)
	case "iis_discovery":
		if !r.endpointModuleOnce("iis_discovery", target) {
			return nil
		}
		return r.runIISDiscovery(ctx, target)
	case "firebase_misconfig":
		if !r.endpointModuleOnce("firebase_misconfig", target) {
			return nil
		}
		return r.runFirebaseMisconfig(ctx, target)
	case "spring_cloud_jolokia":
		if !r.endpointModuleOnce("spring_cloud_jolokia", target) {
			return nil
		}
		return r.runSpringCloudJolokia(ctx, target)
	case "saas_exposure":
		if !r.endpointModuleOnce("saas_exposure", target) {
			return nil
		}
		return r.runSaaSExposure(ctx, target)
	case "cpdos":
		if !r.endpointModuleOnce("cpdos", target) {
			return nil
		}
		return r.runCPDoS(ctx, target)
	case "proxy_path_confusion":
		if !r.endpointModuleOnce("proxy_path_confusion", target) {
			return nil
		}
		return r.runProxyPathConfusion(ctx, target)
	case "ws_cswsh":
		if !r.endpointModuleOnce("ws_cswsh", target) {
			return nil
		}
		return r.runCrossSiteWebSocketHijack(ctx, target)
	case "pdf_injection":
		return r.runPDFInjection(ctx, target)
	case "jsonp_callback":
		return r.runJSONPCallback(ctx, target)
	case "react_rsc_rce":
		if !r.endpointModuleOnce("react_rsc_rce", target) {
			return nil
		}
		return r.runReactRSCRCE(ctx, target)
	case "server_side_js_injection":
		return r.runSSJS(ctx, target)
	case "csti_detection":
		return r.runCSTI(ctx, target)
	case "swagger_exposure":
		if !r.endpointModuleOnce("swagger_exposure", target) {
			return nil
		}
		return r.runSwaggerExposure(ctx, target)
	case "sensitive_file_discovery":
		return r.runSensitiveFiles(ctx, target)
	case "http_smuggling":
		if !r.endpointModuleOnce("http_smuggling", target) {
			return nil
		}
		return r.runHTTPSmuggling(ctx, target)
	case "race_condition_sync":
		return r.runRaceSync(ctx, target)
	case "oauth_flow_audit":
		if !r.endpointModuleOnce("oauth_flow_audit", target) {
			return nil
		}
		return r.runOAuthFlow(ctx, target)
	case "cloud_native_exposure":
		if !r.endpointModuleOnce("cloud_native_exposure", target) {
			return nil
		}
		return r.runCloudNativeExposure(ctx, target)
	case "grpc_scan":
		if !r.endpointModuleOnce("grpc_scan", target) {
			return nil
		}
		return r.runGRPCScan(ctx, target)
	default:
		r.emitSkip(module, target, "unknown module")
		return nil
	}
}
