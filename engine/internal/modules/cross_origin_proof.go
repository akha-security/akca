package modules

import (
	"context"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/verification"
	"strings"
)

type crossOriginReader interface {
	ReadCrossOrigin(context.Context, string, string, string, bool) (string, error)
}

func (r *Runner) proveCrossOriginRead(ctx context.Context, module string, target ScanTarget, kind, callback string, baseline, probe httpclient.RequestResponse) *ModuleFinding {
	reader, ok := r.browser.(crossOriginReader)
	canary := r.privateCanary(module, target)
	if !ok || canary == "" || strings.Contains(probe.Request.URL, canary) || strings.Contains(probe.Request.Body, canary) {
		return nil
	}
	anonymous, err := reader.ReadCrossOrigin(ctx, probe.Request.URL, kind, callback, false)
	if err != nil || strings.Contains(anonymous, canary) {
		return nil
	}
	first, err := reader.ReadCrossOrigin(ctx, probe.Request.URL, kind, callback, true)
	if err != nil || !strings.Contains(first, canary) {
		return nil
	}
	second, err := reader.ReadCrossOrigin(ctx, probe.Request.URL, kind, callback, true)
	if err != nil || !strings.Contains(second, canary) {
		return nil
	}
	signal := "browser_private_read"
	p := defaultPayload(module, signal, callback, signal)
	return r.verifyAndBuildWithCandidate(ctx, module, target, p, baseline, probe, signal, false, false, "", "", func(c *verification.Candidate) {
		c.CrossOriginRead = true
		c.DirectTypedSignal = true
		c.RequestedProofType = verification.ProofCrossOriginRead
		c.NegativeControlSet = true
		c.NegativeControlOK = true
		c.TypedReplayHits = []bool{true, true}
		c.Observations = append(c.Observations,
			verification.NewBrowserReadObservation(r.scanID, module, target.EndpointURL, verification.RoleNegativeControl, 1, anonymous),
			verification.NewBrowserReadObservation(r.scanID, module, target.EndpointURL, verification.RoleCrossOriginRead, 1, first),
			verification.NewBrowserReadObservation(r.scanID, module, target.EndpointURL, verification.RoleCrossOriginRead, 2, second))
	})
}
