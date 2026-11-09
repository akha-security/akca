package app

import (
	"context"

	"github.com/akha-security/akca/engine/internal/jsanalyzer"
)

func (e *Engine) runJSAnalysisPhase(ctx context.Context) error {
	if !e.session.Config.EnableJSAnalysis {
		return nil
	}
	e.session.SetPhase("js_analysis")
	_ = e.Emit("phase_started", "js analysis", map[string]interface{}{"phase": "js_analysis"})

	analyzer := jsanalyzer.New(e.session.ID, e.client, e.scope, e.db, e.reqQueue, e.Emit)
	workers := 4
	if limit := e.session.Config.MaxConcurrency; limit > 0 {
		workers = min(workers, limit)
	}
	if limit := e.session.Config.PerHostConcurrency; limit > 0 {
		workers = min(workers, limit)
	}
	analyzer.SetConcurrency(workers)
	if err := analyzer.RunFromStorage(ctx); err != nil {
		return err
	}
	_ = e.Emit("phase_finished", "js analysis", map[string]interface{}{"phase": "js_analysis"})
	return nil
}
