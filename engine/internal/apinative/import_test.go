package apinative

import (
	"strings"
	"testing"
)

func TestImportOpenAPIYAMLInventory(t *testing.T) {
	spec := `
openapi: 3.0.3
info:
  title: Orders API
paths:
  /orders/{id}:
    get:
      operationId: getOrder
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
            format: uuid
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                type: object
                properties:
                  id: {type: string}
`
	inventory, err := Import([]byte(spec), ImportOptions{BaseURL: "https://api.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if inventory.Format != FormatOpenAPI || len(inventory.Operations) != 1 {
		t.Fatalf("unexpected inventory: %+v", inventory)
	}
	op := inventory.Operations[0]
	if op.URL != "https://api.example.test/orders/%7Bid%7D" && op.URL != "https://api.example.test/orders/{id}" {
		t.Fatalf("unexpected URL: %s", op.URL)
	}
	if len(op.Parameters) != 1 || op.Parameters[0].Format != "uuid" {
		t.Fatalf("typed parameter missing: %+v", op.Parameters)
	}
}

func TestImportTrafficAndProtocolFormats(t *testing.T) {
	tests := []struct {
		name string
		data string
		want Format
	}{
		{"postman", `{"info":{"name":"C"},"item":[{"name":"users","request":{"method":"GET","url":"https://api.test/users"}}]}`, FormatPostman},
		{"har", `{"log":{"entries":[{"request":{"method":"GET","url":"https://api.test/users","queryString":[]}}]}}`, FormatHAR},
		{"wsdl", `<definitions><service><port><address location="https://api.test/soap"/></port></service><portType><operation name="GetUser"/></portType></definitions>`, FormatWSDL},
		{"graphql", "type Query {\n user(id: ID!): User\n}", FormatGraphQL},
		{"proto", `syntax = "proto3"; service Users { rpc GetUser (GetUserRequest) returns (User); }`, FormatProto},
		{"asyncapi", `{"asyncapi":"2.6.0","channels":{"/events":{"publish":{"operationId":"send","message":{"payload":{"type":"object","properties":{"id":{"type":"string"}}}}}}}}`, FormatAsyncAPI},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inventory, err := Import([]byte(test.data), ImportOptions{BaseURL: "https://api.test"})
			if err != nil {
				t.Fatal(err)
			}
			if inventory.Format != test.want || len(inventory.Operations) == 0 {
				t.Fatalf("unexpected inventory: %+v", inventory)
			}
		})
	}
}

func TestSchemaAwareMutationPreservesJSONShape(t *testing.T) {
	out, err := MutateJSON(`{"user":{"id":"old","active":true}}`, "user.id",
		Mutation{Value: "' OR '1'='1", SchemaValid: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"active":true`) || !strings.Contains(out, `"id":"' OR '1'='1"`) {
		t.Fatalf("shape not preserved: %s", out)
	}
}

func TestDependencyGraphExtractsAndBindsIDs(t *testing.T) {
	graph := NewDependencyGraph()
	found, err := graph.Observe("createOrder", []byte(`{"order":{"id":"ord-7"},"token":"tok-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 {
		t.Fatalf("expected two dependencies, got %+v", found)
	}
	bound, used := graph.Bind(`/orders/{{id}}?token={{token}}`)
	if bound != `/orders/ord-7?token=tok-1` || len(used) != 2 {
		t.Fatalf("unexpected binding: %s %+v", bound, used)
	}
}

func TestOpenAPIRefRequestBodyCreatesInjectableJSONLeafParameters(t *testing.T) {
	spec := `
openapi: 3.0.3
info: {title: Profiles}
paths:
  /profiles:
    post:
      operationId: updateProfile
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/Profile'
      responses:
        "200":
          $ref: '#/components/responses/ProfileResponse'
components:
  schemas:
    Profile:
      type: object
      required: [name]
      properties:
        name: {type: string}
        settings:
          type: object
          properties:
            callback: {type: string, format: uri}
            retries: {type: integer, minimum: 1}
  responses:
    ProfileResponse:
      description: ok
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/Profile'
`
	inventory, err := Import([]byte(spec), ImportOptions{BaseURL: "https://api.test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.Operations) != 1 {
		t.Fatalf("operations = %d, want 1", len(inventory.Operations))
	}
	op := inventory.Operations[0]
	for _, expected := range []string{`"name":"akca"`, `"callback":"https://example.test/"`, `"retries":1`} {
		if !strings.Contains(op.BodyTemplate, expected) {
			t.Fatalf("resolved body template missing %s: %s", expected, op.BodyTemplate)
		}
	}
	parameters := map[string]Parameter{}
	for _, parameter := range op.Parameters {
		parameters[parameter.Name] = parameter
	}
	if !parameters["name"].Required || parameters["settings.callback"].Format != "uri" ||
		parameters["settings.retries"].Minimum == nil {
		t.Fatalf("schema leaf parameters were not preserved: %+v", op.Parameters)
	}
	if op.ResponseSchemas["200"] == nil {
		t.Fatal("referenced response schema was not resolved")
	}
}

func TestImportPostmanEnvironmentAndExpandCollection(t *testing.T) {
	environment, err := Import([]byte(`{
	  "name":"local",
	  "_postman_variable_scope":"environment",
	  "values":[{"key":"baseUrl","value":"https://api.test","enabled":true},
	            {"key":"disabled","value":"secret","enabled":false}]
	}`), ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if environment.Format != FormatPostmanEnvironment || environment.Variables["baseUrl"] != "https://api.test" ||
		environment.Variables["disabled"] != "" {
		t.Fatalf("unexpected environment: %+v", environment)
	}
	collection, err := Import([]byte(`{
	  "info":{"name":"users"},
	  "item":[{"name":"get","request":{"method":"GET","url":"{{baseUrl}}/users"}}]
	}`), ImportOptions{Environment: environment.Variables})
	if err != nil {
		t.Fatal(err)
	}
	if got := collection.Operations[0].URL; got != "https://api.test/users" {
		t.Fatalf("expanded URL = %q", got)
	}
}

func TestGraphQLImportBuildsTypedVariablesAndValidSelection(t *testing.T) {
	inventory, err := Import([]byte(`
type Query {
  user(id: ID!, includeDisabled: Boolean): User
  version: String
}`), ImportOptions{BaseURL: "https://api.test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.Operations) != 2 {
		t.Fatalf("operations = %d, want 2", len(inventory.Operations))
	}
	user := inventory.Operations[0]
	if !strings.Contains(user.BodyTemplate, `$id: ID!`) ||
		!strings.Contains(user.BodyTemplate, `user(id: $id, includeDisabled: $includeDisabled) { __typename }`) {
		t.Fatalf("invalid GraphQL operation template: %s", user.BodyTemplate)
	}
	if len(user.Parameters) != 2 || user.Parameters[0].In != "graphql" {
		t.Fatalf("GraphQL variables not exposed as typed parameters: %+v", user.Parameters)
	}
	if strings.Contains(inventory.Operations[1].BodyTemplate, "__typename") {
		t.Fatalf("scalar GraphQL field must not have a selection set: %s", inventory.Operations[1].BodyTemplate)
	}
}

func TestRAMLImportResolvesIncludedPostBody(t *testing.T) {
	spec := `#%RAML 1.0
title: Users API
baseUri: https://api.test/v1
types:
  UserInput: !include types/user.raml
/users:
  post:
    queryParameters:
      notify?: boolean
    body:
      application/json:
        type: UserInput
`
	userType := []byte("type: object\nproperties:\n  email: string\n  'age?': integer\n")
	inventory, err := Import([]byte(spec), ImportOptions{SourcePath: "api.raml", ExternalFiles: map[string][]byte{"types/user.raml": userType}})
	if err != nil {
		t.Fatal(err)
	}
	if inventory.Format != FormatRAML || len(inventory.Operations) != 1 {
		t.Fatalf("unexpected inventory: %+v", inventory)
	}
	op := inventory.Operations[0]
	if op.Method != "POST" || op.URL != "https://api.test/v1/users" || !strings.Contains(op.BodyTemplate, `"email":"akca"`) {
		t.Fatalf("RAML POST body was not materialized: %+v", op)
	}
	params := map[string]Parameter{}
	for _, p := range op.Parameters {
		params[p.Name] = p
	}
	if params["notify"].Required || !params["email"].Required || params["age"].Required {
		t.Fatalf("RAML parameter constraints lost: %+v", op.Parameters)
	}
}

func TestOpenAPIBundleResolvesExternalRequestSchema(t *testing.T) {
	spec := `openapi: 3.1.0
info: {title: Bundled}
paths:
  /orders:
    post:
      requestBody:
        content:
          application/json:
            schema: {$ref: 'schemas/order.yaml#/Order'}
      responses: {'204': {description: ok}}
`
	schema := []byte("Order:\n  type: object\n  required: [quantity]\n  properties:\n    quantity: {type: integer, minimum: 1}\n")
	inv, err := Import([]byte(spec), ImportOptions{BaseURL: "https://api.test", SourcePath: "openapi.yaml", ExternalFiles: map[string][]byte{"schemas/order.yaml": schema}})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Operations) != 1 || !strings.Contains(inv.Operations[0].BodyTemplate, `"quantity":1`) {
		t.Fatalf("external schema was not resolved: %+v", inv)
	}
}
