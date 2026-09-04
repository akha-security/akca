package apinative

import (
	"fmt"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

func importRAML(data []byte, opts ImportOptions) (Inventory, error) {
	root, err := decodeRAMLDocument(data, opts.SourcePath, opts.ExternalFiles, map[string]bool{}, 0)
	if err != nil {
		return Inventory{}, err
	}
	var raw interface{}
	if err := root.Decode(&raw); err != nil {
		return Inventory{}, fmt.Errorf("decode RAML: %w", err)
	}
	rawMap, ok := raw.(map[string]interface{})
	if !ok {
		return Inventory{}, fmt.Errorf("RAML root must be an object")
	}
	doc := normalizeYAMLMap(rawMap)
	out := Inventory{Title: stringValue(doc["title"]), Format: FormatRAML}
	base := stringValue(doc["baseUri"])
	if base == "" {
		base = opts.BaseURL
	}
	if base != "" {
		out.BaseURLs = []string{base}
	}
	types, _ := doc["types"].(map[string]interface{})
	walkRAMLResources(doc, "", base, types, &out)
	if len(out.Operations) == 0 {
		return Inventory{}, fmt.Errorf("RAML definition contains no HTTP operations")
	}
	return out, nil
}

func decodeRAMLDocument(data []byte, source string, files map[string][]byte, stack map[string]bool, depth int) (*yaml.Node, error) {
	if depth > 16 {
		return nil, fmt.Errorf("RAML include nesting exceeds limit")
	}
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return nil, fmt.Errorf("parse RAML: %w", err)
	}
	if err := resolveRAMLIncludes(&node, source, files, stack, depth); err != nil {
		return nil, err
	}
	return &node, nil
}

func resolveRAMLIncludes(node *yaml.Node, source string, files map[string][]byte, stack map[string]bool, depth int) error {
	if node.Tag == "!include" {
		name := strings.ReplaceAll(strings.TrimSpace(node.Value), "\\", "/")
		resolved := path.Clean(path.Join(path.Dir(strings.ReplaceAll(source, "\\", "/")), name))
		data, key, ok := externalFile(files, resolved, name)
		if !ok {
			return fmt.Errorf("RAML include %q not found in supplied bundle", name)
		}
		if stack[key] {
			return fmt.Errorf("cyclic RAML include %q", name)
		}
		next := make(map[string]bool, len(stack)+1)
		for item, used := range stack {
			next[item] = used
		}
		next[key] = true
		included, err := decodeRAMLDocument(data, key, files, next, depth+1)
		if err != nil {
			return err
		}
		if included.Kind == yaml.DocumentNode && len(included.Content) == 1 {
			*node = *included.Content[0]
		} else {
			*node = *included
		}
		return nil
	}
	for _, child := range node.Content {
		if err := resolveRAMLIncludes(child, source, files, stack, depth); err != nil {
			return err
		}
	}
	return nil
}

func externalFile(files map[string][]byte, names ...string) ([]byte, string, bool) {
	for _, candidate := range names {
		candidate = strings.ToLower(strings.TrimPrefix(path.Clean(strings.ReplaceAll(candidate, "\\", "/")), "./"))
		for key, data := range files {
			normalized := strings.ToLower(strings.TrimPrefix(path.Clean(strings.ReplaceAll(key, "\\", "/")), "./"))
			if normalized == candidate {
				return data, normalized, true
			}
		}
	}
	return nil, "", false
}

func walkRAMLResources(container map[string]interface{}, prefix, base string, types map[string]interface{}, out *Inventory) {
	keys := sortedKeys(container)
	for _, key := range keys {
		if !strings.HasPrefix(key, "/") {
			continue
		}
		resource, ok := container[key].(map[string]interface{})
		if !ok {
			continue
		}
		endpointPath := prefix + key
		for _, method := range []string{"get", "post", "put", "patch", "delete", "head", "options"} {
			raw, ok := resource[method].(map[string]interface{})
			if !ok {
				continue
			}
			op := Operation{ID: stringValue(raw["displayName"]), Method: strings.ToUpper(method), Path: endpointPath, SourceFormat: FormatRAML, ResponseSchemas: map[string]interface{}{}}
			if op.ID == "" {
				op.ID = method + "_" + strings.Trim(strings.ReplaceAll(endpointPath, "/", "_"), "_")
			}
			op.Parameters = append(op.Parameters, ramlParameters(resource["uriParameters"], "path", types)...)
			op.Parameters = append(op.Parameters, ramlParameters(raw["uriParameters"], "path", types)...)
			op.Parameters = append(op.Parameters, ramlParameters(raw["queryParameters"], "query", types)...)
			op.Parameters = append(op.Parameters, ramlParameters(raw["headers"], "header", types)...)
			if bodies, ok := raw["body"].(map[string]interface{}); ok {
				contentTypes := sortedKeys(bodies)
				if len(contentTypes) > 0 {
					op.ContentType = contentTypes[0]
					op.RequestSchema = ramlSchema(bodies[contentTypes[0]], types, map[string]bool{})
					op.BodyTemplate = RequestBodyFromSchema(op.RequestSchema)
					op.Parameters = append(op.Parameters, RequestBodyParameters(op.RequestSchema)...)
				}
			}
			op.URL = joinURL(base, endpointPath)
			out.Operations = append(out.Operations, op)
		}
		walkRAMLResources(resource, endpointPath, base, types, out)
	}
}

func ramlParameters(raw interface{}, location string, types map[string]interface{}) []Parameter {
	items, _ := raw.(map[string]interface{})
	keys := sortedKeys(items)
	out := make([]Parameter, 0, len(keys))
	for _, name := range keys {
		required := !strings.HasSuffix(name, "?")
		clean := strings.TrimSuffix(name, "?")
		schema := ramlSchema(items[name], types, map[string]bool{})
		mapped, _ := schema.(map[string]interface{})
		p := Parameter{Name: clean, In: location, Required: required, Type: stringValue(mapped["type"]), Format: stringValue(mapped["format"]), Example: mapped["example"], Schema: schema}
		p.Enum, _ = mapped["enum"].([]interface{})
		out = append(out, p)
	}
	return out
}

func ramlSchema(raw interface{}, types map[string]interface{}, stack map[string]bool) interface{} {
	if text, ok := raw.(string); ok {
		if strings.HasSuffix(text, "[]") {
			return map[string]interface{}{"type": "array", "items": ramlSchema(strings.TrimSuffix(text, "[]"), types, stack)}
		}
		if builtinRAMLType(text) {
			return map[string]interface{}{"type": normalizeRAMLType(text)}
		}
		if target, exists := types[text]; exists && !stack[text] {
			next := make(map[string]bool, len(stack)+1)
			for key, used := range stack {
				next[key] = used
			}
			next[text] = true
			return ramlSchema(target, types, next)
		}
		return map[string]interface{}{"type": "string"}
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return map[string]interface{}{"type": "string"}
	}
	typeName := stringValue(m["type"])
	var result map[string]interface{}
	if typeName != "" && !builtinRAMLType(typeName) {
		base, _ := ramlSchema(typeName, types, stack).(map[string]interface{})
		result = cloneMap(base)
	} else {
		result = map[string]interface{}{}
	}
	for key, value := range m {
		if key == "type" && typeName != "" && !builtinRAMLType(typeName) {
			continue
		}
		result[key] = value
	}
	if typeName != "" && builtinRAMLType(typeName) {
		result["type"] = normalizeRAMLType(typeName)
	}
	_, propertiesDeclaredHere := m["properties"]
	if props, ok := result["properties"].(map[string]interface{}); ok && propertiesDeclaredHere {
		converted := map[string]interface{}{}
		required := []interface{}{}
		keys := sortedKeys(props)
		for _, name := range keys {
			clean := strings.TrimSuffix(name, "?")
			converted[clean] = ramlSchema(props[name], types, stack)
			explicitOptional := false
			if property, ok := props[name].(map[string]interface{}); ok && property["required"] == false {
				explicitOptional = true
			}
			if !strings.HasSuffix(name, "?") && !explicitOptional {
				required = append(required, clean)
			}
		}
		result["properties"] = converted
		if len(required) > 0 {
			result["required"] = required
		}
		if result["type"] == nil {
			result["type"] = "object"
		}
	}
	if items, exists := result["items"]; exists {
		result["items"] = ramlSchema(items, types, stack)
	}
	return result
}

func builtinRAMLType(value string) bool {
	switch strings.ToLower(value) {
	case "object", "array", "string", "integer", "number", "boolean", "datetime", "date-only", "nil", "file", "any":
		return true
	}
	return false
}
func normalizeRAMLType(value string) string {
	switch strings.ToLower(value) {
	case "datetime", "date-only":
		return "string"
	case "nil", "file", "any":
		return "string"
	default:
		return strings.ToLower(value)
	}
}
func cloneMap(in map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
