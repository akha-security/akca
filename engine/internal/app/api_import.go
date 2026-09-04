package app

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/akha-security/akca/engine/internal/apinative"
)

func (e *Engine) runAPIImportPhase(ctx context.Context, files []string, baseURL string) error {
	var failures []string
	type definitionFile struct {
		name     string
		data     []byte
		external map[string][]byte
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
		if strings.EqualFold(filepath.Ext(filename), ".zip") {
			bundle, bundleErr := readAPIBundle(data)
			if bundleErr != nil {
				failures = append(failures, filename+": "+bundleErr.Error())
				continue
			}
			for name, item := range bundle {
				if looksLikeAPIDefinition(name, item) {
					definitions = append(definitions, definitionFile{name: name, data: item, external: bundle})
				}
			}
			continue
		}
		definitions = append(definitions, definitionFile{name: filename, data: data})
	}

	// Load Postman environments before collections regardless of CLI file
	// order. Variable values are used only in-memory and are never emitted.
	environment := map[string]string{}
	for _, definition := range definitions {
		inventory, err := apinative.Import(definition.data, apinative.ImportOptions{BaseURL: baseURL, SourcePath: definition.name, ExternalFiles: definition.external})
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
			BaseURL: baseURL, Environment: environment, SourcePath: definition.name, ExternalFiles: definition.external,
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

func readAPIBundle(data []byte) (map[string][]byte, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("open API bundle: %w", err)
	}
	if len(reader.File) > 256 {
		return nil, fmt.Errorf("API bundle contains too many files (%d > 256)", len(reader.File))
	}
	out := map[string][]byte{}
	var total int64
	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		name := strings.ReplaceAll(filepath.ToSlash(file.Name), "\\", "/")
		if strings.HasPrefix(name, "/") || strings.HasPrefix(name, "../") || strings.Contains(name, "/../") {
			return nil, fmt.Errorf("unsafe API bundle entry %q", file.Name)
		}
		if file.UncompressedSize64 > 8<<20 {
			return nil, fmt.Errorf("API bundle entry %q exceeds 8 MiB", file.Name)
		}
		rc, openErr := file.Open()
		if openErr != nil {
			return nil, openErr
		}
		item, readErr := io.ReadAll(io.LimitReader(rc, (8<<20)+1))
		_ = rc.Close()
		if readErr != nil {
			return nil, readErr
		}
		if len(item) > 8<<20 {
			return nil, fmt.Errorf("API bundle entry %q exceeds 8 MiB", file.Name)
		}
		total += int64(len(item))
		if total > 64<<20 {
			return nil, fmt.Errorf("expanded API bundle exceeds 64 MiB")
		}
		out[name] = item
	}
	return out, nil
}

func looksLikeAPIDefinition(name string, data []byte) bool {
	ext := strings.ToLower(filepath.Ext(name))
	trimmed := bytes.TrimSpace(data)
	lower := bytes.ToLower(trimmed)
	if bytes.HasPrefix(trimmed, []byte("#%RAML")) {
		return true
	}
	if ext == ".wsdl" {
		return bytes.Contains(lower, []byte("<definitions"))
	}
	if ext == ".graphql" || ext == ".gql" {
		return bytes.Contains(lower, []byte("type query")) || bytes.Contains(lower, []byte("type mutation"))
	}
	if ext == ".proto" {
		return bytes.Contains(lower, []byte("syntax =")) || bytes.Contains(lower, []byte("service "))
	}
	// A bundle commonly contains JSON/YAML schema fragments. Only root API
	// documents become import jobs; fragments remain available for $ref/include.
	return bytes.Contains(lower, []byte("openapi:")) || bytes.Contains(lower, []byte("\"openapi\"")) ||
		bytes.Contains(lower, []byte("swagger:")) || bytes.Contains(lower, []byte("\"swagger\"")) ||
		bytes.Contains(lower, []byte("asyncapi:")) || bytes.Contains(lower, []byte("\"asyncapi\"")) ||
		(bytes.Contains(lower, []byte("\"log\"")) && bytes.Contains(lower, []byte("\"entries\""))) ||
		(bytes.Contains(lower, []byte("\"info\"")) && bytes.Contains(lower, []byte("\"item\""))) ||
		(bytes.Contains(lower, []byte("\"values\"")) && bytes.Contains(lower, []byte("_postman_variable_scope")))
}
