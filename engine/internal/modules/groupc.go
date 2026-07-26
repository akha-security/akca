package modules

import (
	"context"
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
				if r.cfg.AllowsModule("cors") {
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
				if r.cfg.AllowsModule("cache_deception") {
					localFindings = append(localFindings, r.runCacheDeception(ctx, target)...)
				}
				if r.cfg.AllowsModule("mass_assignment") {
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
				if r.cfg.AllowsModule("broken_auth") {
					localFindings = append(localFindings, r.runBrokenAuth(ctx, target)...)
				}
				if r.cfg.AllowsModule("csrf") {
					localFindings = append(localFindings, r.runCSRF(ctx, target)...)
				}
				if r.cfg.AllowsModule("wordpress_fuzz") {
					localFindings = append(localFindings, r.runWordPressFuzz(ctx, target)...)
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
