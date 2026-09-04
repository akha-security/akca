package modules

import "context"

// runRaceSync keeps the synchronized-race entry point available, but executes
// the transaction-aware proof engine. It supplies the same capability without
// treating a burst of HTTP 2xx responses as duplicate side effects.
func (r *Runner) runRaceSync(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("race_condition_sync", target); !ok {
		r.emitSkip("race_condition_sync", target, reason)
		return nil
	}
	return r.runRaceConditionProof(ctx, target)
}
