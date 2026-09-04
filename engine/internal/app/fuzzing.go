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
	defer func() {
		var metrics interface{}
		if e.queue403 != nil {
			metrics = e.queue403.Metrics()
		}
		_ = e.Emit("phase_finished", "fuzzing", map[string]interface{}{
			"phase": "fuzzing", "queue_403": metrics,
		})
	}()

	workers := e.session.Config.MaxConcurrency
	if workers <= 0 {
		workers = 6
	}
	fe := fuzzing.NewEngine(e.session.ID, e.client, e.scope, e.db, e.Emit, workers)
	e.queue403 = fe.Queue403()

	fuzzBases := uniqueFuzzBases(targets)
	if len(fuzzBases) == 0 {
		fuzzBases = targets
	}

	hintsByHost := e.fuzzTechHints(fuzzBases)
	if err := fe.RunWithHints(ctx, fuzzBases, hintsByHost); err != nil {
		if ctx.Err() != nil {
			return err
		}
		_ = e.Emit("log", "fuzzing phase encountered non-fatal errors: "+err.Error(), map[string]interface{}{
			"scan_id": e.session.ID, "phase": "fuzzing",
		})
	}
	return nil
}

func uniqueFuzzBases(targets []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, target := range targets {
		host := fuzzing.HostFromURL(target)
		if host == "" {
			continue
		}
		if _, ok := seen[host]; !ok {
			seen[host] = struct{}{}
			out = append(out, target)
		}
	}
	return out
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
