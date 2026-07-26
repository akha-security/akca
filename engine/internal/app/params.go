package app

import (
	"context"

	"github.com/akha-security/akca/engine/internal/params"
)

func (e *Engine) runParameterDiscoveryPhase(ctx context.Context) error {
	e.session.SetPhase("parameter_discovery")
	_ = e.Emit("phase_started", "parameter discovery", map[string]interface{}{"phase": "parameter_discovery"})

	d := params.NewDiscoverer(e.session.ID, e.client, e.scope, e.db, e.Emit)
	d.SetMaxProbes(e.session.Config.ParameterMaxProbes())
	d.SetWordlistCap(e.session.Config.ParameterWordlistCap())
	d.SetParallelism(e.session.Config.ParameterDiscoveryWorkers())
	if err := d.Run(ctx, e.session.Config.ParameterDiscoveryEndpointLimit()); err != nil {
		return err
	}
	_ = e.Emit("phase_finished", "parameter discovery", map[string]interface{}{"phase": "parameter_discovery"})
	return nil
}
