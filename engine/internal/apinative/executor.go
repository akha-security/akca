package apinative

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

type RequestDoer interface {
	Do(context.Context, string, string, []byte, map[string]string) (httpclient.RequestResponse, error)
}

type ReplayResult struct {
	OperationID  string                     `json:"operation_id"`
	Method       string                     `json:"method"`
	URL          string                     `json:"url"`
	Dependencies []string                   `json:"dependencies,omitempty"`
	Extracted    []ExtractedValue           `json:"extracted,omitempty"`
	Response     *httpclient.ResponseRecord `json:"response,omitempty"`
	Error        string                     `json:"error,omitempty"`
	Operation    Operation                  `json:"-"`
}

type ReplaySummary struct {
	Attempted         int            `json:"attempted"`
	Succeeded         int            `json:"succeeded"`
	SkippedUnsafe     int            `json:"skipped_unsafe"`
	DependenciesBound int            `json:"dependencies_bound"`
	DependenciesFound int            `json:"dependencies_found"`
	Results           []ReplayResult `json:"results"`
}

// ReplayReadOnly executes imported read-only operations in definition order.
// JSON IDs/tokens from earlier responses are bound into later path/body
// templates. Write methods are intentionally skipped: API inventory must not
// silently become an irreversible production workflow.
func ReplayReadOnly(ctx context.Context, inventory Inventory, baseURL string, doer RequestDoer) ReplaySummary {
	graph := NewDependencyGraph()
	summary := ReplaySummary{}
	for _, operation := range inventory.Operations {
		method := strings.ToUpper(strings.TrimSpace(operation.Method))
		if method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions {
			summary.SkippedUnsafe++
			continue
		}
		result := ReplayResult{OperationID: operation.ID, Method: method, Operation: operation}
		rawURL, usedURL := graph.Bind(operation.ResolveURL(baseURL))
		rawURL, usedPath := bindPathParameters(rawURL, operation.Parameters, graph)
		body, usedBody := graph.Bind(operation.BodyTemplate)
		result.Dependencies = append(result.Dependencies, usedURL...)
		result.Dependencies = append(result.Dependencies, usedPath...)
		result.Dependencies = append(result.Dependencies, usedBody...)
		result.URL = rawURL
		summary.DependenciesBound += len(result.Dependencies)
		summary.Attempted++

		if unresolvedTemplate(rawURL) {
			result.Error = "unresolved path dependency"
			summary.Results = append(summary.Results, result)
			continue
		}
		headers := map[string]string{}
		if operation.ContentType != "" {
			headers["Content-Type"] = operation.ContentType
		}
		rr, err := doer.Do(ctx, method, rawURL, []byte(body), headers)
		if err != nil {
			result.Error = err.Error()
			summary.Results = append(summary.Results, result)
			continue
		}
		response := rr.Response
		result.Response = &response
		if response.StatusCode >= 200 && response.StatusCode < 400 && strings.TrimSpace(response.Body) != "" {
			if extracted, observeErr := graph.Observe(operation.ID, []byte(response.Body)); observeErr == nil {
				result.Extracted = extracted
				summary.DependenciesFound += len(extracted)
			}
		}
		summary.Succeeded++
		summary.Results = append(summary.Results, result)
	}
	return summary
}

func bindPathParameters(rawURL string, parameters []Parameter, graph *DependencyGraph) (string, []string) {
	var used []string
	for _, parameter := range parameters {
		if !strings.EqualFold(parameter.In, "path") || parameter.Name == "" {
			continue
		}
		value, ok := graph.Value(parameter.Name)
		if ok {
			used = append(used, parameter.Name)
		} else {
			value = parameterExample(parameter)
		}
		if value == nil {
			continue
		}
		replacement := url.PathEscape(stringValue(value))
		for _, placeholder := range []string{
			"{" + parameter.Name + "}",
			"%7B" + parameter.Name + "%7D",
			"%7b" + parameter.Name + "%7d",
			":" + parameter.Name,
		} {
			rawURL = strings.ReplaceAll(rawURL, placeholder, replacement)
		}
	}
	return rawURL, used
}

func parameterExample(parameter Parameter) interface{} {
	if parameter.Example != nil {
		return parameter.Example
	}
	if len(parameter.Enum) > 0 {
		return parameter.Enum[0]
	}
	if schema, ok := parameter.Schema.(map[string]interface{}); ok {
		if value := exampleForSchema(schema, 0); value != nil {
			return value
		}
	}
	schema := map[string]interface{}{"type": parameter.Type, "format": parameter.Format}
	return exampleForSchema(schema, 0)
}

func unresolvedTemplate(value string) bool {
	return strings.Contains(value, "{{") || strings.Contains(value, "}}") ||
		strings.Contains(value, "%7B") || strings.Contains(value, "%7b") ||
		(strings.Contains(value, "{") && strings.Contains(value, "}"))
}

func (s ReplaySummary) Validate() error {
	if s.Attempted == 0 {
		return fmt.Errorf("no read-only API operations were replayed")
	}
	if s.Succeeded == 0 {
		return fmt.Errorf("all read-only API operation replays failed")
	}
	return nil
}
