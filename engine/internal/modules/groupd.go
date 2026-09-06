package modules

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
)

func (r *Runner) RunGroupD(ctx context.Context, targets []ScanTarget) ([]ModuleFinding, error) {
	_ = r.emit("vuln_modules_d_started", "Configuration & exposure scanning started", map[string]interface{}{
		"scan_id": r.scanID, "targets": len(targets),
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

	targetCh := make(chan ScanTarget, moduleQueueCapacity(workers, len(targets)))

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if rec := recover(); rec != nil {
					_ = r.emit("log", fmt.Sprintf("RunGroupD worker recovered from panic: %v", rec), map[string]interface{}{"scan_id": r.scanID})
				}
			}()
			for target := range targetCh {
				if ctx.Err() != nil {
					return
				}
				if r.budgetExhausted.Load() || !r.canModuleProbe("security_headers") {
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
							_ = r.emit("log", fmt.Sprintf("RunGroupD target %s recovered from panic: %v", target.EndpointURL, rec), map[string]interface{}{"scan_id": r.scanID})
						}
					}()
					var localFindings []ModuleFinding
					if r.cfg.AllowsModule("security_headers") {
						localFindings = append(localFindings, r.runSecurityHeaders(ctx, target)...)
					}
					if r.cfg.AllowsModule("cookie_security") {
						localFindings = append(localFindings, r.runCookieSecurity(ctx, target)...)
					}
					if r.cfg.AllowsModule("tls_misconfig") && r.endpointModuleOnce("tls_misconfig", target) {
						localFindings = append(localFindings, r.runTLSMisconfig(ctx, target)...)
					}
					if r.cfg.AllowsModule("vulnerable_components") {
						localFindings = append(localFindings, r.runVulnerableComponents(ctx, target)...)
					}
					if r.cfg.AllowsModule("sensitive_data") {
						localFindings = append(localFindings, r.runSensitiveData(ctx, target)...)
					}
					if r.cfg.AllowsModule("secret_exposure") && r.contentModuleOnce("secret_exposure", target) {
						localFindings = append(localFindings, r.runSecretExposure(ctx, target)...)
					}
					if r.cfg.AllowsModule("cicd_exposure") && r.endpointModuleOnce("cicd_exposure", target) {
						localFindings = append(localFindings, r.runCICDExposure(ctx, target)...)
					}
					if r.cfg.AllowsModule("git_recovery") && r.endpointModuleOnce("git_recovery", target) {
						localFindings = append(localFindings, r.runGitDeepRecovery(ctx, target)...)
					}
					if r.cfg.AllowsModule("source_code_disclosure") {
						localFindings = append(localFindings, r.runSourceCodeDisclosure(ctx, target)...)
					}
					if r.cfg.AllowsModule("graphql") {
						localFindings = append(localFindings, r.runGraphQL(ctx, target)...)
					}
					if r.cfg.AllowsModule("script_source") {
						localFindings = append(localFindings, r.runScriptSource(ctx, target)...)
					}
					if r.cfg.AllowsModule("websocket") {
						localFindings = append(localFindings, r.runWebSocket(ctx, target)...)
					}
					if r.cfg.AllowsModule("cloud_storage") && r.endpointModuleOnce("cloud_storage", target) {
						localFindings = append(localFindings, r.runCloudStorage(ctx, target)...)
					}
					if r.cfg.AllowsModule("cloud_posture") && r.endpointModuleOnce("cloud_posture", target) {
						localFindings = append(localFindings, r.runCloudPosture(ctx, target)...)
					}
					if r.cfg.AllowsModule("client_ssti") {
						localFindings = append(localFindings, r.runClientSSTI(ctx, target)...)
					}
					if r.cfg.AllowsModule("smuggling") && r.endpointModuleOnce("smuggling", target) {
						localFindings = append(localFindings, r.runSmuggling(ctx, target)...)
					}
					if r.cfg.AllowsModule("prototype_pollution") {
						localFindings = append(localFindings, r.runPrototypePollution(ctx, target)...)
					}
					if r.cfg.AllowsModule("insecure_deserialization") {
						localFindings = append(localFindings, r.runInsecureDeserialization(ctx, target)...)
					}
					if r.cfg.AllowsModule("ldap_xpath_injection") {
						localFindings = append(localFindings, r.runLDAPXPathInjection(ctx, target)...)
					}
					if r.cfg.AllowsModule("crlf") {
						localFindings = append(localFindings, r.runCRLF(ctx, target)...)
					}
					if r.cfg.AllowsModule("debug_admin") {
						localFindings = append(localFindings, r.runDebugAdmin(ctx, target)...)
					}
					if r.cfg.AllowsModule("actuator") && r.endpointModuleOnce("actuator", target) {
						localFindings = append(localFindings, r.runSpringActuator(ctx, target)...)
					}
					if r.cfg.AllowsModule("cloud_takeover") && r.endpointModuleOnce("cloud_takeover", target) {
						localFindings = append(localFindings, r.runCloudTakeover(ctx, target)...)
					}
					if r.cfg.AllowsModule("business_logic") {
						localFindings = append(localFindings, r.runBusinessLogic(ctx, target)...)
					}
					if r.cfg.AllowsModule("race_condition") {
						localFindings = append(localFindings, r.runRaceCondition(ctx, target)...)
					}
					if r.cfg.AllowsModule("api_versioning") && r.endpointModuleOnce("api_versioning", target) {
						localFindings = append(localFindings, r.runAPIVersioning(ctx, target)...)
					}
					if r.cfg.AllowsModule("known_cve") {
						localFindings = append(localFindings, r.runKnownCVE(ctx, target)...)
					}
					if r.cfg.AllowsModule("http_methods") && r.endpointModuleOnce("http_methods", target) {
						localFindings = append(localFindings, r.runHTTPMethods(ctx, target)...)
					}
					if r.cfg.AllowsModule("host_poisoning") && r.endpointModuleOnce("host_poisoning", target) {
						localFindings = append(localFindings, r.runHostPoisoning(ctx, target)...)
					}
					if r.cfg.AllowsModule("devops_exposure") && r.endpointModuleOnce("devops_exposure", target) {
						localFindings = append(localFindings, r.runDevOpsExposure(ctx, target)...)
					}
					if r.cfg.AllowsModule("backup_archives") && r.endpointModuleOnce("backup_archives", target) {
						localFindings = append(localFindings, r.runBackupArchives(ctx, target)...)
					}
					if r.cfg.AllowsModule("ldap") {
						localFindings = append(localFindings, r.runLDAPInjection(ctx, target)...)
					}
					if r.cfg.AllowsModule("xpath") {
						localFindings = append(localFindings, r.runXPathInjection(ctx, target)...)
					}

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

	r.releaseUnusedCategoryBudget("client_exposure")
	totalTargets := len(targets)
	tested := int(testedCount.Load())
	skipped := int(skippedBudgetCount.Load())
	coveragePct := 100.0
	if totalTargets > 0 {
		coveragePct = float64(tested) / float64(totalTargets) * 100.0
	}
	_ = r.emit("vuln_modules_d_finished", "Configuration & exposure scanning finished", map[string]interface{}{
		"scan_id": r.scanID, "findings": len(findings),
		"targets_tested": tested, "targets_total": totalTargets,
		"coverage_percentage": fmt.Sprintf("%.1f%%", coveragePct),
	})
	if skipped > 0 {
		r.emitOnce("group_budget_starved:group_d", "coverage_gap",
			fmt.Sprintf("Configuration & exposure scan group was budget-starved: tested %d of %d targets (%.1f%% coverage)", tested, totalTargets, coveragePct),
			map[string]interface{}{
				"scan_id": r.scanID, "group": "group_d",
				"targets_tested": tested, "targets_total": totalTargets,
				"coverage_pct": coveragePct,
			},
		)
	}
	return findings, nil
}

func (r *Runner) RunGroupDFromDB(ctx context.Context, limit int) ([]ModuleFinding, error) {
	targets, err := r.LoadTargetsWithEndpointsFromDB(limit)
	if err != nil {
		return nil, err
	}
	return r.RunGroupD(ctx, targets)
}
