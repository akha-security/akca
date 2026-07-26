package modules

import (
	"context"
	"sync"
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

	targetCh := make(chan ScanTarget, len(targets))
	for _, t := range targets {
		targetCh <- t
	}
	close(targetCh)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range targetCh {
				if ctx.Err() != nil {
					return
				}
				if !r.scope.IsInScope(target.EndpointURL) {
					continue
				}
				var localFindings []ModuleFinding
				if r.cfg.AllowsModule("security_headers") {
					localFindings = append(localFindings, r.runSecurityHeaders(ctx, target)...)
				}
				if r.cfg.AllowsModule("tls_misconfig") {
					localFindings = append(localFindings, r.runTLSMisconfig(ctx, target)...)
				}
				if r.cfg.AllowsModule("vulnerable_components") {
					localFindings = append(localFindings, r.runVulnerableComponents(ctx, target)...)
				}
				if r.cfg.AllowsModule("sensitive_data") {
					localFindings = append(localFindings, r.runSensitiveData(ctx, target)...)
				}
				if r.cfg.AllowsModule("secret_exposure") {
					localFindings = append(localFindings, r.runSecretExposure(ctx, target)...)
				}
				if r.cfg.AllowsModule("cicd_exposure") {
					localFindings = append(localFindings, r.runCICDExposure(ctx, target)...)
				}
				if r.cfg.AllowsModule("git_recovery") {
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
				if r.cfg.AllowsModule("cloud_storage") {
					localFindings = append(localFindings, r.runCloudStorage(ctx, target)...)
				}
				if r.cfg.AllowsModule("cloud_posture") {
					localFindings = append(localFindings, r.runCloudPosture(ctx, target)...)
				}
				if r.cfg.AllowsModule("client_ssti") {
					localFindings = append(localFindings, r.runClientSSTI(ctx, target)...)
				}
				if r.cfg.AllowsModule("smuggling") {
					localFindings = append(localFindings, r.runSmuggling(ctx, target)...)
				}
				if r.cfg.AllowsModule("prototype_pollution") {
					localFindings = append(localFindings, r.runPrototypePollution(ctx, target)...)
				}
				if r.cfg.AllowsModule("ldap_xpath_injection") {
					localFindings = append(localFindings, r.runLDAPXPathInjection(ctx, target)...)
				}
				if r.cfg.AllowsModule("debug_admin") {
					localFindings = append(localFindings, r.runDebugAdmin(ctx, target)...)
				}
				if r.cfg.AllowsModule("business_logic") {
					localFindings = append(localFindings, r.runBusinessLogic(ctx, target)...)
				}
				if r.cfg.AllowsModule("race_condition") {
					localFindings = append(localFindings, r.runRaceCondition(ctx, target)...)
				}
				if r.cfg.AllowsModule("api_versioning") {
					localFindings = append(localFindings, r.runAPIVersioning(ctx, target)...)
				}
				if r.cfg.AllowsModule("known_cve") {
					localFindings = append(localFindings, r.runKnownCVE(ctx, target)...)
				}

				if len(localFindings) > 0 {
					mu.Lock()
					findings = append(findings, localFindings...)
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

	_ = r.emit("vuln_modules_d_finished", "Configuration & exposure scanning finished", map[string]interface{}{
		"scan_id": r.scanID, "findings": len(findings),
	})
	return findings, nil
}

func (r *Runner) RunGroupDFromDB(ctx context.Context, limit int) ([]ModuleFinding, error) {
	targets, err := r.LoadTargetsWithEndpointsFromDB(limit)
	if err != nil {
		return nil, err
	}
	return r.RunGroupD(ctx, targets)
}
