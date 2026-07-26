package app

import (
	"context"

	"github.com/akha-security/akca/engine/internal/learning"
	"github.com/akha-security/akca/engine/internal/wafintel"
)

func (e *Engine) runLearningWAFPhase(ctx context.Context, targets []string, opts wafintel.CalibrationOptions) error {
	e.session.SetPhase("learning_waf")
	_ = e.Emit("phase_started", "learning and waf evasion", map[string]interface{}{"phase": "learning_waf"})

	store := learning.NewStore(e.db)
	for _, target := range targets {
		host := wafintel.HostFromTarget(target)
		if host == "" {
			continue
		}
		p := store.Load(host, target)
		if len(p.Worked)+len(p.Blocked) == 0 {
			_ = store.Save(p)
		}
	}

	runner := wafintel.NewRunner(e.session.ID, e.db, e.Emit)
	runner.SetClient(wafHTTPAdapter{client: e.client})
	if err := runner.CalibrateWithOptions(ctx, targets, opts); err != nil {
		return err
	}

	_ = e.Emit("phase_finished", "learning and waf evasion", map[string]interface{}{"phase": "learning_waf"})
	return nil
}
