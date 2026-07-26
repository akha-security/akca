package app

import (
	"context"

	"github.com/akha-security/akca/engine/internal/fuzzing"
)

func (e *Engine) runFuzzingPhase(ctx context.Context, targets []string) error {
	if !e.session.Config.EnableFuzzing {
		return nil
	}
	e.session.SetPhase("fuzzing")
	_ = e.Emit("phase_started", "fuzzing", map[string]interface{}{"phase": "fuzzing"})

	workers := e.session.Config.MaxConcurrency
	if workers <= 0 {
		workers = 6
	}
	fe := fuzzing.NewEngine(e.session.ID, e.client, e.scope, e.db, e.Emit, workers)
	e.queue403 = fe.Queue403()

	hintsByHost := e.fuzzTechHints(targets)
	if err := fe.RunWithHints(ctx, targets, hintsByHost); err != nil {
		return err
	}
	_ = e.Emit("phase_finished", "fuzzing", map[string]interface{}{
		"phase": "fuzzing", "queue_403": e.queue403.Metrics(),
	})
	return nil
}

func (e *Engine) Queue403() *fuzzing.Queue403 {
	return e.queue403
}

// fuzzTechHints loads the persisted technology fingerprint for each target host
// and turns it into hint tokens that drive technology-aware path probing.
func (e *Engine) fuzzTechHints(targets []string) map[string][]string {
	out := make(map[string][]string)
	for _, target := range targets {
		host := fuzzing.HostFromURL(target)
		if host == "" {
			continue
		}
		if _, ok := out[host]; ok {
			continue
		}
		fp, err := e.db.GetTechFingerprint(e.session.ID, host)
		if err != nil {
			continue
		}
		hints := fp.Hints
		for _, v := range []string{fp.BackendLanguage, fp.Framework, fp.Database, fp.ServerCDN, fp.JSFramework} {
			if v != "" {
				hints = append(hints, v)
			}
		}
		if len(hints) > 0 {
			out[host] = hints
		}
	}
	return out
}
