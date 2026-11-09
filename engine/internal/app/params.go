package app

import (
	"context"

	"github.com/akha-security/akca/engine/internal/params"
)

func (e *Engine) runParameterDiscoveryPhase(ctx context.Context) error {
	const phase = "parameter_discovery"
	e.session.SetPhase(phase)
	_ = e.Emit("phase_started", "parameter discovery", map[string]interface{}{"phase": phase})

	d := params.NewDiscoverer(e.session.ID, e.client, e.scope, e.db, e.Emit)
	d.SetForcedActiveURLs(e.session.Config.ForceActiveScanURLs)
	d.SetMaxProbes(e.session.Config.ParameterMaxProbes())
	d.SetWordlistCap(e.session.Config.ParameterWordlistCap())
	d.SetMaxHits(e.session.Config.ParameterMaxHits())
	d.SetMaxTransferProbes(e.session.Config.ParameterTransferMaxProbes())
	d.SetParallelism(e.session.Config.ParameterDiscoveryWorkers())
	limit := e.session.Config.ParameterDiscoveryEndpointLimit()
	// Run the configured GET and body-method discovery once, before the
	// vulnerability modules need its inputs.
	if err := d.Run(ctx, limit); err != nil {
		return err
	}
	_ = e.Emit("phase_finished", "parameter discovery", map[string]interface{}{"phase": phase})
	return nil
}
