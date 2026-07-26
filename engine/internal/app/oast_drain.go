package app

import (
	"context"

	"github.com/akha-security/akca/engine/internal/modules"
)

func (e *Engine) runOASTDrainPhase(ctx context.Context, scanID string) {
	if !e.session.Config.EnableOAST || e.oast == nil {
		_ = e.Emit("phase_started", "oast_drain", map[string]interface{}{"phase": "oast_drain", "skipped": true})
		_ = e.Emit("phase_finished", "oast_drain", map[string]interface{}{"phase": "oast_drain", "skipped": true})
		return
	}
	duration := e.session.Config.OASTDrainDuration()
	if duration <= 0 {
		_ = e.Emit("phase_started", "oast_drain", map[string]interface{}{"phase": "oast_drain", "skipped": true})
		_ = e.Emit("phase_finished", "oast_drain", map[string]interface{}{"phase": "oast_drain", "skipped": true})
		return
	}

	e.session.SetPhase("oast_drain")
	before, _ := e.db.CountOASTCallbacks(scanID)
	_ = e.Emit("phase_started", "OAST callback drain", map[string]interface{}{
		"phase": "oast_drain", "duration_sec": int(duration.Seconds()), "pending_correlations": e.oast.CorrelationCount(),
	})

	e.oast.Drain(ctx, duration)

	after, _ := e.db.CountOASTCallbacks(scanID)
	newCallbacks := after - before
	if newCallbacks < 0 {
		newCallbacks = 0
	}

	// Finalization is intentionally unconditional: a callback can arrive
	// between the last module probe and the initial drain count.
	if _, err := modules.FinalizeOASTFindings(e.db, scanID, e.Emit); err != nil {
		_ = e.Emit("scan_error", err.Error(), map[string]interface{}{"phase": "oast_drain", "step": "finalize_findings"})
	}

	_ = e.Emit("phase_finished", "OAST callback drain complete", map[string]interface{}{
		"phase": "oast_drain", "callbacks_received": newCallbacks, "total_callbacks": after,
	})
}
