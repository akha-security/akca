package modules

import (
	"context"
	"strings"
)

// RunIntegrationSubset executes a bounded set of modules used by the integration test lab.
func (r *Runner) RunIntegrationSubset(ctx context.Context, targets []ScanTarget) ([]ModuleFinding, error) {
	var findings []ModuleFinding
	for _, target := range targets {
		if !r.scope.IsInScope(target.EndpointURL) {
			continue
		}
		path := strings.ToLower(target.EndpointURL)
		switch {
		case strings.Contains(path, "/search"):
			findings = append(findings, r.runXSS(ctx, target)...)
		case strings.Contains(path, "/api/fetch"):
			findings = append(findings, r.runSSRF(ctx, target)...)
		case strings.Contains(path, "/api/users"):
			findings = append(findings, r.runSQLi(ctx, target)...)
		case strings.Contains(path, "/download"):
			findings = append(findings, r.runLFI(ctx, target)...)
		case strings.Contains(path, "/xml"):
			findings = append(findings, r.runXXE(ctx, target)...)
		case strings.Contains(path, "/redirect"):
			findings = append(findings, r.runOpenRedirect(ctx, target)...)
		case strings.Contains(path, "/graphql"):
			findings = append(findings, r.runGraphQL(ctx, target)...)
		case strings.Contains(path, "/profile"):
			findings = append(findings, r.runSensitiveData(ctx, target)...)
		case strings.Contains(path, "/static/") || strings.Contains(path, ".js"):
			findings = append(findings, r.runSecretExposure(ctx, target)...)
		case strings.Contains(path, "/actuator"):
			findings = append(findings, r.runDebugAdmin(ctx, target)...)
		case strings.Contains(path, "/coupon"):
			findings = append(findings, r.runRaceCondition(ctx, target)...)
		case strings.Contains(path, "/waf-probe"):
			findings = append(findings, r.runXSS(ctx, target)...)
		}
	}
	findings = append(findings, r.flushDelayedTimingVerifications(ctx)...)
	_ = r.emit("vuln_modules_subset_finished", "integration module subset finished", map[string]interface{}{
		"scan_id": r.scanID, "findings": len(findings), "targets": len(targets),
	})
	return findings, nil
}
