package graphqlattack

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/testfixtures"
)

func TestGraphQLRejectsCapabilitiesAndFalsePositives(t *testing.T) {
	stripePublishable := strings.Join([]string{"pk", "live", "123456789012345678901234"}, "_")
	for _, body := range []string{
		`{"data":{"user":{"isAdmin":false,"password":null,"token":""}}}`,
		`{"data":{"message":"password token apiKey"},"extensions":{"tracing":{}}}`,
		`{"errors":[{"message":"cannot use $where; expected type Int; Did you mean users?"}]}`,
		`{"data":{"admin":null}}`,
		`[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]`,
		`{"data":{"a1":{},"a2":{},"a5":{}}}`,
		`{"data":{"user":{"apiKey":"` + stripePublishable + `"}}}`,
		`{"data":{"user":{"token":"[REDACTED]"}}}`,
		`{"data":{"config":{"key":"-----BEGIN PRIVATE KEY-----"}}}`,
		`{"data":{"user":{"value":"AKCA_GQL_9991_EVAL"}}}`,
		`<html>__schema types at f (/app/a.js:10:20)</html>`,
		`{"query":"{ __schema { types { name } } }"}`,
	} {
		if got := Signals(body); len(got) != 0 {
			t.Errorf("false positive %v for %s", got, body)
		}
	}
}

func TestGraphQLDisclosureSignals(t *testing.T) {
	stripeSecret := strings.Join([]string{"sk", "live", "A1b2C3d4E5f6G7h8I9j0K1l2"}, "_")
	cases := []struct{ body, signal string }{
		{`{"errors":[{"message":"resolver failed","extensions":{"exception":{"stacktrace":["Error: failed","at resolve (/srv/api/resolver.js:10:20)"]}}}]}`, "graphql_stack_trace_disclosure"},
		{`{"errors":[{"message":"SQLSTATE[42P01]: relation does not exist"}]}`, "graphql_database_error_disclosure"},
		{`{"data":{"config":{"key":"` + stripeSecret + `"}}}`, "graphql_server_secret_exposure"},
		{`{"data":{"config":{"aws":"` + testfixtures.AWSDetectableAccessKey() + `"}}}`, "graphql_server_secret_exposure"},
	}
	for _, tt := range cases {
		if !Confirmed(tt.body, tt.signal) {
			t.Errorf("missing %s", tt.signal)
		}
		if ok, _ := Analyze(tt.body, tt.body, Probe{}); !ok {
			t.Errorf("persistent %s suppressed", tt.signal)
		}
	}
}

func TestGraphQLSchemaProbes(t *testing.T) {
	body := `{"data":{"__schema":{"queryType":{"name":"Root"},"types":[
 {"name":"Mutation","fields":[{"name":"deleteUser","type":{"kind":"SCALAR","name":"Boolean"}}]},
 {"name":"Other","fields":[{"name":"wrong","type":{"kind":"SCALAR","name":"String"}}]},
 {"name":"Root","fields":[
 {"name":"needsID","args":[{"name":"id","type":{"kind":"NON_NULL"}}],"type":{"kind":"OBJECT","name":"Account"}},
 {"name":"viewer","args":[],"type":{"kind":"OBJECT","name":"Account"}},
 {"name":"Viewer","args":[],"type":{"kind":"SCALAR","name":"String"}},
 {"name":"withDefault","args":[{"name":"x","defaultValue":"1","type":{"kind":"NON_NULL"}}],"type":{"kind":"SCALAR","name":"Int"}},
 {"name":"1invalid","type":{"kind":"SCALAR","name":"String"}}]},
 {"name":"Account","fields":[
 {"name":"apiKey","type":{"kind":"SCALAR","name":"String"}},
 {"name":"password","args":[{"name":"id","type":{"kind":"NON_NULL"}}],"type":{"kind":"SCALAR","name":"String"}}]}
 ]}}}`
	probes := SchemaProbes(body)
	if len(probes) != 3 {
		t.Fatalf("probes=%+v", probes)
	}
	if !strings.Contains(probes[0].Body, "viewer { __typename apiKey }") {
		t.Fatal(probes[0])
	}
	if !strings.Contains(probes[1].Body, "Viewer") {
		t.Fatal("case-sensitive name lost")
	}
	if HasSchema(`{"query":"__schema types"}`) {
		t.Fatal("reflected query counted as schema")
	}
}

func TestGraphQLProbeSafetyAndBudget(t *testing.T) {
	for _, p := range DiscoveryProbes() {
		if !json.Valid([]byte(p.Body)) {
			t.Fatalf("invalid JSON: %s", p.Body)
		}
		if strings.Contains(p.Body, "mutation") || strings.Contains(p.Body, "$where") {
			t.Fatal("unsafe probe")
		}
	}
	var batch []interface{}
	_ = json.Unmarshal([]byte(BuildBatchProbe(1000).Body), &batch)
	if len(batch) > 20 {
		t.Fatal("unbounded batch")
	}
}
