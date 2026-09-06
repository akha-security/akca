package modules

import (
	"context"
	"fmt"
	"sync"
)

func (r *Runner) RunGroupC(ctx context.Context, targets []ScanTarget) ([]ModuleFinding, error) {
	_ = r.emit("vuln_modules_c_started", "Authentication & API security scanning started", map[string]interface{}{
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

	targetCh := make(chan ScanTarget, moduleQueueCapacity(workers, len(targets)))

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if rec := recover(); rec != nil {
					_ = r.emit("log", fmt.Sprintf("RunGroupC worker recovered from panic: %v", rec), map[string]interface{}{"scan_id": r.scanID})
				}
			}()
			for target := range targetCh {
				if ctx.Err() != nil {
					return
				}
				if r.budgetExhausted.Load() {
					continue
				}
				if !r.scope.IsInScope(target.EndpointURL) {
					continue
				}
				func() {
					defer func() {
						if rec := recover(); rec != nil {
							_ = r.emit("log", fmt.Sprintf("RunGroupC target %s recovered from panic: %v", target.EndpointURL, rec), map[string]interface{}{"scan_id": r.scanID})
						}
					}()
					var localFindings []ModuleFinding
					if r.cfg.AllowsModule("cors") && r.endpointModuleOnce("cors", target) {
						localFindings = append(localFindings, r.runCORS(ctx, target)...)
					}
					if r.cfg.AllowsModule("jwt") {
						localFindings = append(localFindings, r.runJWT(ctx, target)...)
					}
					if r.cfg.AllowsModule("oauth") {
						localFindings = append(localFindings, r.runOAuth(ctx, target)...)
					}
					if r.cfg.AllowsModule("cache_poisoning") {
						localFindings = append(localFindings, r.runCachePoisoning(ctx, target)...)
					}
					if r.cfg.AllowsModule("cache_deception") && r.endpointModuleOnce("cache_deception", target) {
						localFindings = append(localFindings, r.runCacheDeception(ctx, target)...)
					}
					if r.cfg.AllowsModule("mass_assignment") && r.endpointModuleOnce("mass_assignment", target) {
						localFindings = append(localFindings, r.runMassAssignment(ctx, target)...)
					}
					if r.cfg.AllowsModule("api_exposure") {
						localFindings = append(localFindings, r.runAPIExposure(ctx, target)...)
					}
					if r.cfg.AllowsModule("rate_limit") {
						localFindings = append(localFindings, r.runRateLimit(ctx, target)...)
					}
					if r.cfg.AllowsModule("account_enum") {
						localFindings = append(localFindings, r.runAccountEnum(ctx, target)...)
					}
					if r.cfg.AllowsModule("hpp") {
						localFindings = append(localFindings, r.runHPP(ctx, target)...)
					}
					if r.cfg.AllowsModule("broken_auth") && r.endpointModuleOnce("broken_auth", target) {
						localFindings = append(localFindings, r.runBrokenAuth(ctx, target)...)
					}
					if r.cfg.AllowsModule("crlf") {
						localFindings = append(localFindings, r.runCRLF(ctx, target)...)
					}
					if r.cfg.AllowsModule("xpath") {
						localFindings = append(localFindings, r.runXPathInjection(ctx, target)...)
					}
					if r.cfg.AllowsModule("ldap") {
						localFindings = append(localFindings, r.runLDAPInjection(ctx, target)...)
					}
					if r.cfg.AllowsModule("graphql") {
						localFindings = append(localFindings, r.runGraphQL(ctx, target)...)
					}
					if r.cfg.AllowsModule("websocket") {
						localFindings = append(localFindings, r.runWebSocket(ctx, target)...)
					}
					if r.cfg.AllowsModule("business_logic") {
						localFindings = append(localFindings, r.runBusinessLogic(ctx, target)...)
					}
					if r.cfg.AllowsModule("race_condition") {
						localFindings = append(localFindings, r.runRaceCondition(ctx, target)...)
					}
					if r.cfg.AllowsModule("smuggling") {
						localFindings = append(localFindings, r.runSmuggling(ctx, target)...)
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

	_ = r.emit("vuln_modules_c_finished", "Authentication & API security scanning finished", map[string]interface{}{
		"scan_id": r.scanID, "findings": len(findings),
	})
	return findings, nil
}

func (r *Runner) RunGroupCFromDB(ctx context.Context, limit int) ([]ModuleFinding, error) {
	targets, err := r.LoadTargetsWithEndpointsFromDB(limit)
	if err != nil {
		return nil, err
	}
	return r.RunGroupC(ctx, targets)
}
