package specingest

import (
	"encoding/json"
	"fmt"
	"strings"
)

// openAPIDoc holds generic structure for both OpenAPI 3.x and Swagger 2.0.
type openAPIDoc struct {
	OpenAPI string `json:"openapi"`
	Swagger string `json:"swagger"`
	Info    struct {
		Title   string `json:"title"`
		Version string `json:"version"`
	} `json:"info"`
	Host     string `json:"host"`
	BasePath string `json:"basePath"`
	Servers  []struct {
		URL string `json:"url"`
	} `json:"servers"`
	Paths map[string]map[string]openAPIOperation `json:"paths"`
}

type openAPIOperation struct {
	Summary     string             `json:"summary"`
	Description string             `json:"description"`
	Tags        []string           `json:"tags"`
	Parameters  []openAPIParameter `json:"parameters"`
	RequestBody *struct {
		Content map[string]struct {
			Schema map[string]interface{} `json:"schema"`
		} `json:"content"`
	} `json:"requestBody"`
}

type openAPIParameter struct {
	Name        string                 `json:"name"`
	In          string                 `json:"in"`
	Required    bool                   `json:"required"`
	Description string                 `json:"description"`
	Type        string                 `json:"type"`
	Schema      map[string]interface{} `json:"schema"`
	Enum        []interface{}          `json:"enum"`
}

func parseOpenAPI(data []byte) (*IngestResult, error) {
	var doc openAPIDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	format := FormatOpenAPI3
	if doc.Swagger != "" {
		format = FormatSwagger2
	} else if doc.OpenAPI == "" && len(doc.Paths) == 0 {
		return nil, fmt.Errorf("not an OpenAPI/Swagger document")
	}

	baseURL := ""
	if len(doc.Servers) > 0 && doc.Servers[0].URL != "" {
		baseURL = doc.Servers[0].URL
	} else if doc.Host != "" {
		scheme := "https"
		baseURL = fmt.Sprintf("%s://%s%s", scheme, doc.Host, doc.BasePath)
	}

	var endpoints []ParsedEndpoint
	httpMethods := map[string]bool{
		"get": true, "post": true, "put": true, "delete": true,
		"patch": true, "options": true, "head": true,
	}

	for path, methods := range doc.Paths {
		for method, op := range methods {
			methodLower := strings.ToLower(method)
			if !httpMethods[methodLower] {
				continue
			}

			endpoint := ParsedEndpoint{
				Method:      strings.ToUpper(methodLower),
				Path:        path,
				Summary:     op.Summary,
				Description: op.Description,
				Tags:        op.Tags,
				Headers:     make(map[string]string),
			}

			// Extract parameters
			for _, param := range op.Parameters {
				loc := LocationQuery
				switch strings.ToLower(param.In) {
				case "path":
					loc = LocationPath
				case "header":
					loc = LocationHeader
				case "cookie":
					loc = LocationCookie
				case "body", "formData":
					loc = LocationBody
				}

				pType := param.Type
				if pType == "" && param.Schema != nil {
					if t, ok := param.Schema["type"].(string); ok {
						pType = t
					}
				}

				var enumVals []string
				for _, e := range param.Enum {
					enumVals = append(enumVals, fmt.Sprint(e))
				}

				endpoint.Parameters = append(endpoint.Parameters, ParameterSpec{
					Name:        param.Name,
					Location:    loc,
					Required:    param.Required,
					Type:        pType,
					Description: param.Description,
					EnumValues:  enumVals,
				})
			}

			// Extract request body for OpenAPI 3
			if op.RequestBody != nil && len(op.RequestBody.Content) > 0 {
				for ct, content := range op.RequestBody.Content {
					endpoint.ContentType = ct
					if content.Schema != nil {
						mockBody := generateMockJSONFromSchema(content.Schema)
						if b, err := json.Marshal(mockBody); err == nil {
							endpoint.BodyTemplate = string(b)
						}
					}
					break
				}
			}

			endpoints = append(endpoints, endpoint)
		}
	}

	return &IngestResult{
		Format:    format,
		Title:     doc.Info.Title,
		Version:   doc.Info.Version,
		BaseURL:   baseURL,
		Endpoints: endpoints,
	}, nil
}

func generateMockJSONFromSchema(schema map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	if props, ok := schema["properties"].(map[string]interface{}); ok {
		for propName, propVal := range props {
			if propMap, isMap := propVal.(map[string]interface{}); isMap {
				pType, _ := propMap["type"].(string)
				switch pType {
				case "integer", "number":
					result[propName] = 1
				case "boolean":
					result[propName] = true
				case "array":
					result[propName] = []interface{}{}
				default:
					result[propName] = "test"
				}
			} else {
				result[propName] = "test"
			}
		}
	}
	return result
}
