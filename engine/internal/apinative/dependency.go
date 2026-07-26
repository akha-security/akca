package apinative

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

type ExtractedValue struct {
	OperationID string      `json:"operation_id"`
	Path        string      `json:"path"`
	Value       interface{} `json:"value"`
}

type DependencyGraph struct {
	values map[string]ExtractedValue
}

func NewDependencyGraph() *DependencyGraph {
	return &DependencyGraph{values: make(map[string]ExtractedValue)}
}

var dependencyKeyRE = regexp.MustCompile(`(?i)(^id$|_id$|^token$|^cursor$|^next$|^location$)`)

func (g *DependencyGraph) Observe(operationID string, responseBody []byte) ([]ExtractedValue, error) {
	var value interface{}
	if err := json.Unmarshal(responseBody, &value); err != nil {
		return nil, err
	}
	var found []ExtractedValue
	collectDependencies(operationID, "", value, &found)
	for _, item := range found {
		g.values[operationID+"."+item.Path] = item
		g.values[item.Path] = item
		last := item.Path
		if index := strings.LastIndex(last, "."); index >= 0 {
			last = last[index+1:]
		}
		g.values[last] = item
	}
	return found, nil
}

func collectDependencies(operationID, prefix string, value interface{}, out *[]ExtractedValue) {
	switch typed := value.(type) {
	case map[string]interface{}:
		keys := sortedKeys(typed)
		for _, key := range keys {
			child := typed[key]
			path := key
			if prefix != "" {
				path = prefix + "." + key
			}
			if dependencyKeyRE.MatchString(key) && scalar(child) {
				*out = append(*out, ExtractedValue{OperationID: operationID, Path: path, Value: child})
			}
			collectDependencies(operationID, path, child, out)
		}
	case []interface{}:
		for index, child := range typed {
			collectDependencies(operationID, fmt.Sprintf("%s.%d", prefix, index), child, out)
		}
	}
}

func (g *DependencyGraph) Bind(template string) (string, []string) {
	keys := make([]string, 0, len(g.values))
	for key := range g.values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	var used []string
	for _, key := range keys {
		placeholder := "{{" + key + "}}"
		if strings.Contains(template, placeholder) {
			template = strings.ReplaceAll(template, placeholder, stringValue(g.values[key].Value))
			used = append(used, key)
		}
	}
	return template, used
}

func (g *DependencyGraph) Value(key string) (interface{}, bool) {
	item, ok := g.values[key]
	if !ok {
		return nil, false
	}
	return item.Value, true
}

func scalar(value interface{}) bool {
	switch value.(type) {
	case string, float64, bool, nil:
		return true
	default:
		return false
	}
}
