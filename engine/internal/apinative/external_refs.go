package apinative

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

func resolveBundledOpenAPIRefs(root map[string]interface{}, source string, files map[string][]byte) (map[string]interface{}, error) {
	resolved, err := resolveExternalValue(root, source, files, map[string]bool{}, 0)
	if err != nil {
		return nil, err
	}
	out, ok := resolved.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("resolved OpenAPI root is not an object")
	}
	return out, nil
}

func resolveExternalValue(value interface{}, source string, files map[string][]byte, stack map[string]bool, depth int) (interface{}, error) {
	if depth > 32 {
		return nil, fmt.Errorf("OpenAPI external reference nesting exceeds limit")
	}
	switch typed := value.(type) {
	case []interface{}:
		out := make([]interface{}, len(typed))
		for i, child := range typed {
			resolved, err := resolveExternalValue(child, source, files, stack, depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = resolved
		}
		return out, nil
	case map[string]interface{}:
		ref := stringValue(typed["$ref"])
		if ref != "" && !strings.HasPrefix(ref, "#/") {
			parts := strings.SplitN(ref, "#", 2)
			fileRef := parts[0]
			name := path.Clean(path.Join(path.Dir(strings.ReplaceAll(source, "\\", "/")), fileRef))
			data, key, ok := externalFile(files, name, fileRef)
			if !ok {
				return nil, fmt.Errorf("OpenAPI reference %q not found in supplied bundle", ref)
			}
			stackKey := key + "#"
			if len(parts) == 2 {
				stackKey += parts[1]
			}
			if stack[stackKey] {
				return nil, fmt.Errorf("cyclic OpenAPI reference %q", ref)
			}
			doc, err := decodeExternalObject(data)
			if err != nil {
				return nil, fmt.Errorf("decode OpenAPI reference %q: %w", ref, err)
			}
			var target interface{} = doc
			if len(parts) == 2 && parts[1] != "" {
				var found bool
				target, found = localRef(doc, "#/"+strings.TrimPrefix(parts[1], "/"))
				if !found {
					return nil, fmt.Errorf("OpenAPI reference fragment %q not found", ref)
				}
			}
			next := make(map[string]bool, len(stack)+1)
			for k, v := range stack {
				next[k] = v
			}
			next[stackKey] = true
			resolved, err := resolveExternalValue(target, key, files, next, depth+1)
			if err != nil {
				return nil, err
			}
			resolvedMap, ok := resolved.(map[string]interface{})
			if !ok {
				return resolved, nil
			}
			merged := cloneMap(resolvedMap)
			for k, child := range typed {
				if k == "$ref" {
					continue
				}
				item, childErr := resolveExternalValue(child, source, files, stack, depth+1)
				if childErr != nil {
					return nil, childErr
				}
				merged[k] = item
			}
			return merged, nil
		}
		out := make(map[string]interface{}, len(typed))
		for k, child := range typed {
			resolved, err := resolveExternalValue(child, source, files, stack, depth+1)
			if err != nil {
				return nil, err
			}
			out[k] = resolved
		}
		return out, nil
	default:
		return value, nil
	}
}

func decodeExternalObject(data []byte) (map[string]interface{}, error) {
	var doc map[string]interface{}
	if json.Unmarshal(bytes.TrimSpace(data), &doc) == nil {
		return doc, nil
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return normalizeYAMLMap(doc), nil
}
