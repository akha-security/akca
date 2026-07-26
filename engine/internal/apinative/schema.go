package apinative

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type Mutation struct {
	Value       interface{} `json:"value"`
	SchemaValid bool        `json:"schema_valid"`
	Reason      string      `json:"reason"`
}

func SchemaAwareMutations(parameter Parameter, vulnClass string) []Mutation {
	kind := strings.ToLower(parameter.Type)
	if kind == "" {
		if schema, ok := parameter.Schema.(map[string]interface{}); ok {
			kind = strings.ToLower(stringValue(schema["type"]))
		}
	}
	switch kind {
	case "integer", "number":
		values := []float64{0, -1}
		if parameter.Minimum != nil {
			values = append(values, *parameter.Minimum)
		}
		if parameter.Maximum != nil {
			values = append(values, *parameter.Maximum)
		}
		out := make([]Mutation, 0, len(values))
		for _, value := range values {
			if kind == "integer" {
				out = append(out, Mutation{Value: int64(value), SchemaValid: true, Reason: "numeric_boundary"})
			} else {
				out = append(out, Mutation{Value: value, SchemaValid: true, Reason: "numeric_boundary"})
			}
		}
		return out
	case "boolean":
		return []Mutation{{Value: true, SchemaValid: true, Reason: "boolean_true"}, {Value: false, SchemaValid: true, Reason: "boolean_false"}}
	case "array":
		return []Mutation{{Value: []interface{}{}, SchemaValid: true, Reason: "empty_array"}}
	case "object":
		return []Mutation{{Value: map[string]interface{}{}, SchemaValid: true, Reason: "empty_object"}}
	default:
		return stringMutations(parameter, vulnClass)
	}
}

func stringMutations(parameter Parameter, vulnClass string) []Mutation {
	if len(parameter.Enum) > 0 {
		return []Mutation{{Value: parameter.Enum[0], SchemaValid: true, Reason: "enum_member"}}
	}
	var values []string
	switch strings.ToLower(vulnClass) {
	case "sqli":
		values = []string{"' OR '1'='1'-- -", "' OR '1'='2'-- -"}
	case "xss":
		values = []string{`"><svg onload=window.__akca_xss_confirmed=1>`}
	case "ssrf":
		values = []string{"https://akca.invalid/"}
	case "ssti":
		values = []string{"{{7*7}}"}
	default:
		values = []string{"akca", "", strings.Repeat("A", 256)}
	}
	out := make([]Mutation, 0, len(values))
	for _, value := range values {
		out = append(out, Mutation{Value: value, SchemaValid: true, Reason: "typed_string_payload"})
	}
	return out
}

func MutateJSON(body, dottedPath string, mutation Mutation) (string, error) {
	var document interface{}
	decoder := json.NewDecoder(strings.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return "", err
	}
	parts := strings.Split(dottedPath, ".")
	if err := setJSONPath(document, parts, mutation.Value); err != nil {
		return "", err
	}
	raw, err := json.Marshal(document)
	return string(raw), err
}

func setJSONPath(current interface{}, parts []string, value interface{}) error {
	if len(parts) == 0 {
		return fmt.Errorf("empty JSON path")
	}
	if object, ok := current.(map[string]interface{}); ok {
		if len(parts) == 1 {
			if _, exists := object[parts[0]]; !exists {
				return fmt.Errorf("JSON path not found: %s", parts[0])
			}
			object[parts[0]] = value
			return nil
		}
		next, exists := object[parts[0]]
		if !exists {
			return fmt.Errorf("JSON path not found: %s", parts[0])
		}
		return setJSONPath(next, parts[1:], value)
	}
	if array, ok := current.([]interface{}); ok {
		index, err := strconv.Atoi(parts[0])
		if err != nil || index < 0 || index >= len(array) {
			return fmt.Errorf("invalid array index: %s", parts[0])
		}
		if len(parts) == 1 {
			array[index] = value
			return nil
		}
		return setJSONPath(array[index], parts[1:], value)
	}
	return fmt.Errorf("cannot descend into %T", current)
}
