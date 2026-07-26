package modules

import "context"

// sqliProbeAttempts is kept for backward compatibility; use injectionProbeAttempts.
func (r *Runner) sqliProbeAttempts(ctx context.Context, target ScanTarget, value string) []InjectionAttempt {
	return r.injectionProbeAttempts(ctx, target, value)
}

func pickSQLiProbe(attempts []InjectionAttempt, baselineBody string) InjectionAttempt {
	return pickBodyDiffAttempt(attempts, baselineBody)
}
