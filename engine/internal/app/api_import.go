package app

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/akha-security/akca/engine/internal/apinative"
)

func (e *Engine) runAPIImportPhase(ctx context.Context, files []string, baseURL string) error {
	var failures []string
	type definitionFile struct {
		name string
		data []byte
	}
	definitions := make([]definitionFile, 0, len(files))
	for _, filename := range files {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		data, err := os.ReadFile(filename)
		if err != nil {
			failures = append(failures, filename+": "+err.Error())
			continue
		}
		definitions = append(definitions, definitionFile{name: filename, data: data})
	}

	// Load Postman environments before collections regardless of CLI file
	// order. Variable values are used only in-memory and are never emitted.
	environment := map[string]string{}
	for _, definition := range definitions {
		inventory, err := apinative.Import(definition.data, apinative.ImportOptions{BaseURL: baseURL})
		if err == nil && inventory.Format == apinative.FormatPostmanEnvironment {
			for key, value := range inventory.Variables {
				environment[key] = value
			}
		}
	}

	imported := 0
	totalOperations := 0
	skippedOutOfScope := 0
	replayInventory := apinative.Inventory{}
	for _, definition := range definitions {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		inventory, err := apinative.Import(definition.data, apinative.ImportOptions{
			BaseURL: baseURL, Environment: environment,
		})
		if err != nil {
			failures = append(failures, definition.name+": "+err.Error())
			continue
		}
		if inventory.Format == apinative.FormatPostmanEnvironment {
			continue
		}
		totalOperations += len(inventory.Operations)
		for _, operation := range inventory.Operations {
			endpointURL := operation.ResolveURL(baseURL)
			if !e.scope.IsInScope(endpointURL) {
				skippedOutOfScope++
				_ = e.Emit("api_operation_skipped", "imported API operation is outside scan scope",
					map[string]interface{}{"url": endpointURL, "operation_id": operation.ID})
				continue
			}
			replayInventory.Operations = append(replayInventory.Operations, operation)
			trail := map[string]interface{}{
				"url": endpointURL, "method": operation.Method, "normalized_url": endpointURL,
				"source": "api_import", "confidence": 1.0,
				"why_discovered": "Imported " + string(inventory.Format) + " operation " + operation.ID,
				"operation_id":   operation.ID, "source_format": inventory.Format,
				"auth_schemes": operation.AuthSchemes, "response_schemas": operation.ResponseSchemas,
				"request_template": map[string]interface{}{
					"body": operation.BodyTemplate, "content_type": operation.ContentType,
					"request_schema": operation.RequestSchema,
				},
			}
			if err := e.db.SaveDiscoveredEndpoint(e.currentSession().ID, trail); err != nil {
				failures = append(failures, operation.ID+": "+err.Error())
				continue
			}
			endpointID, err := e.db.GetEndpointID(e.currentSession().ID, endpointURL, operation.Method)
			if err == nil {
				for _, parameter := range operation.Parameters {
					priority := 60
					if parameter.Required {
						priority = 80
					}
					_ = e.db.SaveParameter(endpointID, parameter.Name, parameter.In, priority)
				}
			}
			imported++
		}
	}
	replay := apinative.ReplayReadOnly(ctx, replayInventory, baseURL, e.client)
	replayFailures := 0
	for _, result := range replay.Results {
		if result.Error != "" {
			replayFailures++
			continue
		}
		if result.Response == nil || result.Response.StatusCode < 200 || result.Response.StatusCode >= 400 {
			continue
		}
		templateURL := result.Operation.ResolveURL(baseURL)
		if result.URL == templateURL {
			continue
		}
		trail := map[string]interface{}{
			"url": result.URL, "method": result.Method, "normalized_url": result.URL,
			"source": "api_dependency_replay", "confidence": 1.0,
			"why_discovered": "Read-only API replay with response dependency binding",
			"operation_id":   result.OperationID, "dependencies": result.Dependencies,
			"request_template": map[string]interface{}{
				"body": result.Operation.BodyTemplate, "content_type": result.Operation.ContentType,
				"request_schema": result.Operation.RequestSchema, "response_status": result.Response.StatusCode,
			},
		}
		if err := e.db.SaveDiscoveredEndpoint(e.currentSession().ID, trail); err != nil {
			failures = append(failures, result.OperationID+" replay: "+err.Error())
			continue
		}
		endpointID, err := e.db.GetEndpointID(e.currentSession().ID, result.URL, result.Method)
		if err == nil {
			for _, parameter := range result.Operation.Parameters {
				priority := 60
				if parameter.Required {
					priority = 80
				}
				_ = e.db.SaveParameter(endpointID, parameter.Name, parameter.In, priority)
			}
		}
	}
	_ = e.Emit("api_readonly_replay_finished", "read-only API dependency replay finished",
		map[string]interface{}{
			"attempted": replay.Attempted, "succeeded": replay.Succeeded,
			"skipped_unsafe": replay.SkippedUnsafe, "failures": replayFailures,
			"dependencies_bound": replay.DependenciesBound, "dependencies_found": replay.DependenciesFound,
		})
	coverage := 1.0
	inScopeTotal := totalOperations - skippedOutOfScope
	if inScopeTotal > 0 {
		coverage = float64(imported) / float64(inScopeTotal)
	}
	_ = e.Emit("api_import_finished", "API definitions imported",
		map[string]interface{}{
			"operations": imported, "operations_total": totalOperations,
			"operations_in_scope": inScopeTotal, "skipped_out_of_scope": skippedOutOfScope,
			"inventory_coverage": coverage, "files": len(files), "failures": failures,
		})
	if len(failures) > 0 {
		return fmt.Errorf("API import completed with errors: %s", strings.Join(failures, "; "))
	}
	return nil
}
