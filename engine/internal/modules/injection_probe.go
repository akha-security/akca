package modules

import (
	"context"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

// InjectionAttempt records one probe delivery surface (query, form, header, …).
type InjectionAttempt struct {
	RR      httpclient.RequestResponse
	Target  ScanTarget
	Surface string
}

// injectionProbeAttempts delivers a payload only to the parameter surface that
// discovery identified. A header parameter must stay a header, a query
// parameter must stay in the query string, and a body parameter must keep its
// body encoding. Fan-out across unrelated surfaces changes the request method
// and can turn routing errors (for example, a synthetic POST returning 405)
// into incorrectly attributed injection findings.
func (r *Runner) injectionProbeAttempts(ctx context.Context, target ScanTarget, value string) []InjectionAttempt {
	return r.injectionProbeAttemptsForModule(ctx, "", target, value)
}

func (r *Runner) injectionProbeAttemptsForModule(ctx context.Context, module string, target ScanTarget, value string) []InjectionAttempt {
	location := strings.ToLower(strings.TrimSpace(target.Location))
	if location == "" {
		location = strings.ToLower(strings.TrimSpace(target.Profile.ParameterLocation))
	}
	if location == "" {
		// BuildProbeRequest historically treats an unknown location as query.
		// Keep that fallback explicit without inventing additional surfaces.
		location = "query"
	}

	probeTarget := target
	probeTarget.Location = location
	if strings.TrimSpace(probeTarget.Parameter) == "" {
		probeTarget.Parameter = "q"
	}

	rr, err := r.probeForModule(ctx, module, probeTarget, value)
	if err != nil {
		return nil
	}
	return []InjectionAttempt{{
		RR:      rr,
		Target:  probeTarget,
		Surface: "native:" + location,
	}}
}

// pickBodyDiffAttempt returns the first attempt whose response body differs from baseline.
func pickBodyDiffAttempt(attempts []InjectionAttempt, baselineBody string) InjectionAttempt {
	for _, a := range attempts {
		if a.RR.Response.Body != baselineBody {
			return a
		}
	}
	if len(attempts) > 0 {
		return attempts[0]
	}
	return InjectionAttempt{}
}

// pickSlowestAttempt returns the attempt with the longest response time (timing blind).
func pickSlowestAttempt(attempts []InjectionAttempt) InjectionAttempt {
	best := InjectionAttempt{}
	var bestMs int64
	for _, a := range attempts {
		ms := a.RR.Response.Duration.Milliseconds()
		if ms > bestMs {
			bestMs = ms
			best = a
		}
	}
	if bestMs == 0 && len(attempts) > 0 {
		return attempts[0]
	}
	return best
}
