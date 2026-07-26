package app

import (
	"context"

	"github.com/akha-security/akca/engine/internal/shadowapi"
	"github.com/akha-security/akca/engine/internal/storage"
)

func (e *Engine) runShadowAPIPhase(ctx context.Context, scanID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	observations, err := e.db.ListEndpointObservations(scanID)
	if err != nil {
		return err
	}
	operations := make([]shadowapi.Operation, 0, len(observations))
	for _, observation := range observations {
		operations = append(operations, shadowapi.Operation{
			URL: observation.URL, Method: observation.Method, Source: observation.Source,
		})
	}
	analyzed := shadowapi.Analyze(operations)
	diffs := make([]storage.ShadowAPIDiff, 0, len(analyzed))
	counts := map[string]int{
		shadowapi.UndocumentedRuntime: 0,
		shadowapi.DocumentedUnseen:    0,
		shadowapi.MethodDrift:         0,
	}
	for _, diff := range analyzed {
		counts[diff.Kind]++
		diffs = append(diffs, storage.ShadowAPIDiff{
			ScanID: scanID, Kind: diff.Kind, Method: diff.Method, Path: diff.Path,
			DocumentedMethod: diff.DocumentedMethod, ObservedMethod: diff.ObservedMethod,
			Source: diff.Source, Detail: diff.Detail,
		})
	}
	if err := e.db.ReplaceShadowAPIDiffs(scanID, diffs); err != nil {
		return err
	}
	return e.Emit("shadow_api_analysis_finished", "documented and observed API surfaces compared",
		map[string]interface{}{
			"scan_id": scanID, "differences": len(diffs),
			"undocumented_runtime":    counts[shadowapi.UndocumentedRuntime],
			"documented_not_observed": counts[shadowapi.DocumentedUnseen],
			"method_drift":            counts[shadowapi.MethodDrift],
		})
}
