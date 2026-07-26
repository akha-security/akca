package app

import (
	"context"

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
	be := bypass403.NewEngine(e.session.ID, e.client, e.scope, e.db, e.queue403, e.Emit, workers)
	if err := be.Run(ctx); err != nil {
		return err
	}
	_ = e.Emit("phase_finished", "auth bypass", map[string]interface{}{
		"phase": "auth_bypass", "queue_403": e.queue403.Metrics(),
	})
	return nil
}
