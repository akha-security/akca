package app

import (
	"context"
	"errors"
	"time"

	"github.com/akha-security/akca/engine/internal/bypass403"
)

func (e *Engine) runBypass403Phase(ctx context.Context) error {
	if !e.session.Config.Enable403BypassChecks || e.queue403 == nil {
		return nil
	}
	e.session.SetPhase("auth_bypass")
	_ = e.Emit("phase_started", "auth bypass", map[string]interface{}{"phase": "auth_bypass"})

	workers := 2
	if e.session.Config.MaxConcurrency > 0 && e.session.Config.MaxConcurrency < workers {
		workers = e.session.Config.MaxConcurrency
	}
	phaseCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	be := bypass403.NewEngine(e.session.ID, e.client, e.scope, e.db, e.queue403, e.Emit, workers)
	if err := be.Run(phaseCtx); err != nil {
		return err
	}
	if errors.Is(phaseCtx.Err(), context.DeadlineExceeded) {
		_ = e.Emit("bypass403_budget_exhausted", "auth bypass phase time budget exhausted", map[string]interface{}{
			"phase": "auth_bypass", "timeout_sec": 180, "queue_403": e.queue403.Metrics(),
		})
	}
	_ = e.Emit("phase_finished", "auth bypass", map[string]interface{}{
		"phase": "auth_bypass", "queue_403": e.queue403.Metrics(),
	})
	return nil
}
