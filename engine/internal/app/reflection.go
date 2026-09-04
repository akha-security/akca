package app

import (
	"context"

	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/reflection"
)

func (e *Engine) runReflectionPayloadPhase(ctx context.Context) error {
	e.session.SetPhase("reflection")
	_ = e.Emit("phase_started", "reflection and payload generation", map[string]interface{}{"phase": "reflection"})

	ra := reflection.NewAnalyzer(e.session.ID, e.client, e.scope, e.db, e.Emit)
	limit := e.session.Config.ReflectionProfileLimit()
	ra.SetMaxParams(limit)
	if e.session.Config.RequestBudget > 0 && (limit <= 0 || e.session.Config.RequestBudget < limit) {
		limit = e.session.Config.RequestBudget / 2
		ra.SetMaxParams(e.session.Config.RequestBudget / 2)
	}
	profiles, err := ra.Run(ctx, limit)
	if err != nil {
		return err
	}

	pg := payloadgen.NewGenerator(e.session.ID, e.db, e.session.Config, e.Emit)
	if _, err := pg.Run(ctx, profiles); err != nil {
		return err
	}

	_ = e.Emit("phase_finished", "reflection and payload generation", map[string]interface{}{
		"phase": "reflection", "profiles": len(profiles),
	})
	return nil
}
