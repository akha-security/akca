package specingest

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
)

// Ingest automatically detects the specification format and parses endpoints.
func Ingest(data []byte, filename, defaultBaseURL string) (*IngestResult, error) {
	trimmed := strings.TrimSpace(string(data))
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty specification data")
	}

	ext := strings.ToLower(filepath.Ext(filename))

	// 1. Try HAR
	if ext == ".har" || strings.Contains(trimmed, `"log"`) && strings.Contains(trimmed, `"entries"`) {
		if res, err := parseHAR(data); err == nil {
			applyDefaultBaseURL(res, defaultBaseURL)
			return res, nil
		}
	}

	// 2. Try Postman
	if strings.Contains(trimmed, "schema.getpostman.com") || (strings.Contains(trimmed, `"info"`) && strings.Contains(trimmed, `"item"`)) {
		if res, err := parsePostman(data); err == nil {
			applyDefaultBaseURL(res, defaultBaseURL)
			return res, nil
		}
	}

	// 3. Try OpenAPI / Swagger JSON
	if strings.HasPrefix(trimmed, "{") {
		if res, err := parseOpenAPI(data); err == nil {
			applyDefaultBaseURL(res, defaultBaseURL)
			return res, nil
		}
	}

	// 4. Try basic YAML to JSON conversion for YAML OpenAPI specs
	if ext == ".yaml" || ext == ".yml" || strings.HasPrefix(trimmed, "openapi:") || strings.HasPrefix(trimmed, "swagger:") {
		jsonData, err := basicYAMLToJSON(data)
		if err == nil {
			if res, err := parseOpenAPI(jsonData); err == nil {
				applyDefaultBaseURL(res, defaultBaseURL)
				return res, nil
			}
		}
	}

	return nil, fmt.Errorf("unrecognized specification format for %s", filename)
}

func applyDefaultBaseURL(res *IngestResult, defaultBaseURL string) {
	if res.BaseURL == "" && defaultBaseURL != "" {
		res.BaseURL = strings.TrimRight(defaultBaseURL, "/")
	}
	for i := range res.Endpoints {
		if !strings.HasPrefix(res.Endpoints[i].Path, "http://") && !strings.HasPrefix(res.Endpoints[i].Path, "https://") {
			if res.BaseURL != "" {
				base := strings.TrimRight(res.BaseURL, "/")
				path := "/" + strings.TrimLeft(res.Endpoints[i].Path, "/")
				res.Endpoints[i].Path = base + path
			}
		}
	}
}

// basicYAMLToJSON provides a lightweight fallback YAML to JSON translator for OpenAPI specs.
func basicYAMLToJSON(data []byte) ([]byte, error) {
	// If it's already JSON
	if json.Valid(data) {
		return data, nil
	}

	lines := strings.Split(string(data), "\n")
	doc := make(map[string]interface{})
	paths := make(map[string]interface{})
	var currentPath string
	var currentMethod string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "openapi:") {
			doc["openapi"] = strings.TrimSpace(strings.TrimPrefix(trimmed, "openapi:"))
		} else if strings.HasPrefix(trimmed, "swagger:") {
			doc["swagger"] = strings.TrimSpace(strings.TrimPrefix(trimmed, "swagger:"))
		} else if strings.HasPrefix(trimmed, "title:") {
			if _, ok := doc["info"]; !ok {
				doc["info"] = map[string]interface{}{"title": strings.TrimSpace(strings.TrimPrefix(trimmed, "title:"))}
			}
		} else if strings.HasPrefix(line, "  /") {
			currentPath = strings.TrimSuffix(strings.TrimSpace(line), ":")
			if _, exists := paths[currentPath]; !exists {
				paths[currentPath] = make(map[string]interface{})
			}
		} else if strings.HasPrefix(line, "    ") && (strings.HasPrefix(trimmed, "get:") || strings.HasPrefix(trimmed, "post:") || strings.HasPrefix(trimmed, "put:") || strings.HasPrefix(trimmed, "delete:") || strings.HasPrefix(trimmed, "patch:")) {
			currentMethod = strings.TrimSuffix(trimmed, ":")
			if currentPath != "" {
				if pMap, ok := paths[currentPath].(map[string]interface{}); ok {
					pMap[currentMethod] = map[string]interface{}{}
				}
			}
		}
	}

	doc["paths"] = paths
	return json.Marshal(doc)
}

// NormalizedTarget represents a target ready to be fed into Akca scanner.
type NormalizedTarget struct {
	URL          string            `json:"url"`
	Method       string            `json:"method"`
	Parameter    string            `json:"parameter"`
	Location     string            `json:"location"`
	Headers      map[string]string `json:"headers,omitempty"`
	BodyTemplate string            `json:"body_template,omitempty"`
	ContentType  string            `json:"content_type,omitempty"`
}

// ToTargets converts ingested endpoints into individual parameter attack targets.
func ToTargets(result *IngestResult) []NormalizedTarget {
	var targets []NormalizedTarget

	for _, ep := range result.Endpoints {
		targetURL := ep.Path
		if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
			if result.BaseURL != "" {
				targetURL = strings.TrimRight(result.BaseURL, "/") + "/" + strings.TrimLeft(targetURL, "/")
			}
		}

		// Replace path parameters {id} with test values
		for _, param := range ep.Parameters {
			if param.Location == LocationPath {
				placeholder := "{" + param.Name + "}"
				val := param.Default
				if val == "" {
					val = "100"
				}
				targetURL = strings.ReplaceAll(targetURL, placeholder, val)
			}
		}

		if len(ep.Parameters) == 0 {
			// Parameterless endpoint target
			targets = append(targets, NormalizedTarget{
				URL:          targetURL,
				Method:       ep.Method,
				Headers:      ep.Headers,
				BodyTemplate: ep.BodyTemplate,
				ContentType:  ep.ContentType,
			})
			continue
		}

		for _, param := range ep.Parameters {
			targets = append(targets, NormalizedTarget{
				URL:          targetURL,
				Method:       ep.Method,
				Parameter:    param.Name,
				Location:     string(param.Location),
				Headers:      ep.Headers,
				BodyTemplate: ep.BodyTemplate,
				ContentType:  ep.ContentType,
			})
		}
	}

	return targets
}

func parseURLQuery(rawURL string) url.Values {
	u, err := url.Parse(rawURL)
	if err != nil {
		return url.Values{}
	}
	return u.Query()
}
