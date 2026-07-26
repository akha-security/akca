package app

import (
	"context"

	"github.com/akha-security/akca/engine/internal/modules"
)

func (e *Engine) runVulnModulesPhaseA(ctx context.Context) error {
	e.session.SetPhase("vuln_modules_a")
	_ = e.Emit("phase_started", "Injection vulnerability scanning", map[string]interface{}{"phase": "vuln_modules_a"})

	var oastClient modules.OASTClient
	if e.oast != nil {
		oastClient = e.oast
	}
	runner := modules.NewRunner(e.session.ID, e.client, e.scope, e.db, e.verifier, oastClient, e.Emit, e.session.Config, e.moduleRunnerOpts()...)
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

	var oastClient modules.OASTClient
	if e.oast != nil {
		oastClient = e.oast
	}
	runner := modules.NewRunner(e.session.ID, e.client, e.scope, e.db, e.verifier, oastClient, e.Emit, e.session.Config, e.moduleRunnerOpts()...)
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

	var oastClient modules.OASTClient
	if e.oast != nil {
		oastClient = e.oast
	}
	runner := modules.NewRunner(e.session.ID, e.client, e.scope, e.db, e.verifier, oastClient, e.Emit, e.session.Config, e.moduleRunnerOpts()...)
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

	var oastClient modules.OASTClient
	if e.oast != nil {
		oastClient = e.oast
	}
	runner := modules.NewRunner(e.session.ID, e.client, e.scope, e.db, e.verifier, oastClient, e.Emit, e.session.Config, e.moduleRunnerOpts()...)
	findings, err := runner.RunGroupDFromDB(ctx, e.moduleTargetLimit())
	if err != nil {
		return err
	}
	_ = e.Emit("phase_finished", "Configuration & exposure scanning", map[string]interface{}{
		"phase": "vuln_modules_d", "findings": len(findings),
	})
	return nil
}
