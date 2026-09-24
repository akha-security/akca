package graphqlattack

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/akha-security/akca/engine/internal/secretscan"
)

type Probe struct{ Body, Name, Signal string }

const IntrospectionQuery = `{"query":"{ __schema { queryType { name } types { kind name fields { name args { name defaultValue type { kind name ofType { kind name ofType { kind name } } } } type { kind name ofType { kind name ofType { kind name } } } } } } }"}`
const BaselineQuery = `{"query":"{ __typename }"}`

func queryProbe(query, name string) Probe {
	raw, _ := json.Marshal(map[string]string{"query": query})
	return Probe{Body: string(raw), Name: name}
}

// Only bounded, read-only operations are used. Acceptance is not a vulnerability.
func DiscoveryProbes() []Probe {
	return []Probe{
		queryProbe("{ akca_nonexistent_field_xyz }", "validation_error"),
		{Body: `{"query":"query($v:Int!){__typename}","variables":{"v":"akca-invalid-int"}}`, Name: "variable_validation"},
		queryProbe("{ _service { sdl } }", "federation_schema"),
		BuildBatchProbe(2),
	}
}

func BuildBatchProbe(count int) Probe {
	if count < 1 {
		count = 2
	}
	if count > 20 {
		count = 20
	}
	ops := make([]map[string]string, count)
	for i := range ops {
		ops[i] = map[string]string{"query": "{ __typename }"}
	}
	raw, _ := json.Marshal(ops)
	return Probe{Body: string(raw), Name: "batch_capability", Signal: "graphql_batch_accepted"}
}
func BuildSuggestionsProbe(field string) Probe {
	if !nameRE.MatchString(field) {
		field = "akca"
	}
	return queryProbe("{ "+field+"_nonexistent_field_xyz }", "field_suggestions")
}

// Retained for callers testing validation, never interpreted as authorization proof.
func BuildTypeInversionProbes(field string) []Probe {
	if !nameRE.MatchString(field) {
		return nil
	}
	return []Probe{queryProbe(fmt.Sprintf("{ %s(id:true) { __typename } }", field), "bool_id"),
		queryProbe(fmt.Sprintf("{ %s(id:[1,2,3]) { __typename } }", field), "array_id")}
}

var nameRE = regexp.MustCompile(`^[_A-Za-z][_0-9A-Za-z]*$`)

type typeRef struct {
	Kind   string
	Name   string
	OfType *typeRef
}
type argument struct {
	Name         string
	DefaultValue *string
	Type         typeRef
}
type field struct {
	Name string
	Args []argument
	Type typeRef
}
type schemaType struct {
	Kind, Name string
	Fields     []field
}
type schema struct {
	QueryType struct{ Name string }
	Types     []schemaType
}

func parseSchema(body string) (schema, bool) {
	var doc struct {
		Data struct {
			Schema *schema `json:"__schema"`
		}
	}
	if json.Unmarshal([]byte(body), &doc) != nil || doc.Data.Schema == nil || len(doc.Data.Schema.Types) == 0 {
		return schema{}, false
	}
	return *doc.Data.Schema, true
}
func HasSchema(body string) bool { _, ok := parseSchema(body); return ok }
func unwrap(t typeRef) typeRef {
	for t.OfType != nil {
		t = *t.OfType
	}
	return t
}
func callable(f field) bool {
	if !nameRE.MatchString(f.Name) || strings.HasPrefix(f.Name, "__") {
		return false
	}
	for _, arg := range f.Args {
		if arg.Type.Kind == "NON_NULL" && arg.DefaultValue == nil {
			return false
		}
	}
	return true
}

// SchemaProbes only follows the actual query root. Required arguments are not
// guessed (in particular, IDs are never guessed). Unknown types are skipped.
func SchemaProbes(body string) []Probe {
	s, ok := parseSchema(body)
	if !ok {
		return nil
	}
	types := map[string]schemaType{}
	for _, t := range s.Types {
		types[t.Name] = t
	}
	root := s.QueryType.Name
	if root == "" {
		root = "Query"
	}
	var probes []Probe
	for _, f := range types[root].Fields {
		if !callable(f) {
			continue
		}
		t := unwrap(f.Type)
		selection := ""
		switch t.Kind {
		case "SCALAR", "ENUM":
		case "OBJECT", "INTERFACE":
			selection = " { __typename"
			count := 0
			for _, child := range types[t.Name].Fields {
				ct := unwrap(child.Type)
				if callable(child) && (ct.Kind == "SCALAR" || ct.Kind == "ENUM") && sensitiveName(child.Name) {
					selection += " " + child.Name
					count++
					if count == 8 {
						break
					}
				}
			}
			selection += " }"
		case "UNION":
			selection = " { __typename }"
		default:
			continue
		}
		probes = append(probes, queryProbe("{ "+f.Name+selection+" }", "schema_"+f.Name))
		if len(probes) == 24 {
			break
		}
	}
	return probes
}
func sensitiveName(s string) bool {
	s = strings.ToLower(s)
	for _, part := range []string{"secret", "password", "token", "credential", "config", "connection", "key"} {
		if strings.Contains(s, part) {
			return true
		}
	}
	return false
}

var stackRE = regexp.MustCompile(`(?m)(?:\bat\s+[^\r\n]*[(/\\][^\r\n]+:[0-9]+:[0-9]+\)?|File "[/\\][^"]+", line [0-9]+|\bat\s+[\w.$]+\([^)]+\.java:[0-9]+\))`)
var databaseRE = regexp.MustCompile(`(?i)(?:SQLSTATE\[[A-Z0-9]{5}\]|org\.postgresql\.util\.PSQLException|com\.mysql\.[\w.]*Exception|ORA-[0-9]{5}:)`)

// Signals parses GraphQL envelopes and inspects structured evidence, not field
// names or generic validation errors. Multiple independent disclosures may coexist.
func Signals(body string) []string {
	var raw interface{}
	if json.Unmarshal([]byte(body), &raw) != nil {
		return nil
	}
	found := map[string]bool{}
	var envelope func(interface{})
	envelope = func(v interface{}) {
		if list, ok := v.([]interface{}); ok {
			for _, item := range list {
				envelope(item)
			}
			return
		}
		obj, ok := v.(map[string]interface{})
		if !ok {
			return
		}
		if errs, ok := obj["errors"].([]interface{}); ok {
			for _, e := range errs {
				errObj, ok := e.(map[string]interface{})
				if !ok {
					continue
				}
				message, _ := errObj["message"].(string)
				if databaseRE.MatchString(message) {
					found["graphql_database_error_disclosure"] = true
				}
				// Stack frames must be in an error message or structured error extensions.
				if stackRE.MatchString(message) {
					found["graphql_stack_trace_disclosure"] = true
				}
				if ext, ok := errObj["extensions"].(map[string]interface{}); ok {
					inspectStacks(ext, found)
				}
			}
		}
		if data, exists := obj["data"]; exists {
			inspectSecrets(data, found)
		}
	}
	envelope(raw)
	var out []string
	for _, signal := range []string{"graphql_stack_trace_disclosure", "graphql_database_error_disclosure", "graphql_server_secret_exposure"} {
		if found[signal] {
			out = append(out, signal)
		}
	}
	return out
}
func inspectStacks(v interface{}, found map[string]bool) {
	switch x := v.(type) {
	case map[string]interface{}:
		for k, value := range x {
			if strings.EqualFold(k, "stacktrace") || strings.EqualFold(k, "stack") {
				text, _ := json.Marshal(value)
				if stackRE.Match(text) {
					found["graphql_stack_trace_disclosure"] = true
				}
			} else if strings.EqualFold(k, "exception") {
				inspectStacks(value, found)
			}
		}
	}
}
func inspectSecrets(v interface{}, found map[string]bool) {
	switch x := v.(type) {
	case map[string]interface{}:
		for k, value := range x {
			if !strings.HasPrefix(k, "__") {
				inspectSecrets(value, found)
			}
		}
	case []interface{}:
		for _, value := range x {
			inspectSecrets(value, found)
		}
	case string:
		for _, m := range secretscan.Detect(x) {
			if m.Kind == "private_key" && !strings.Contains(x, "-----END ") {
				continue
			}
			if secretscan.IsReportable(m) {
				found["graphql_server_secret_exposure"] = true
			}
		}
	}
}
func Confirmed(body, signal string) bool {
	for _, s := range Signals(body) {
		if s == signal {
			return true
		}
	}
	return false
}
func Analyze(baselineBody, probeBody string, probe Probe) (bool, string) {
	signals := Signals(probeBody)
	if len(signals) == 0 {
		return false, ""
	}
	return true, signals[0]
}
