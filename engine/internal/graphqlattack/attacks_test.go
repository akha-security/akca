package graphqlattack

import (
	"strings"
	"testing"
)

func TestBuildBatchProbe(t *testing.T) {
	p := BuildBatchProbe(20)
	if !strings.Contains(p.Body, `"query"`) {
		t.Fatal("expected batch json")
	}
}

func TestTypeInversionAnalyze(t *testing.T) {
	probe := BuildTypeInversionProbes("user")[1]
	ok, sig := Analyze(`{"data":{"user":{"id":1}}}`, `{"data":{"users":[{"id":1,"email":"a@b.com"},{"id":2,"email":"c@d.com"}]}}`, probe)
	if !ok {
		t.Fatal("expected type inversion signal")
	}
	if sig == "" {
		t.Fatal("expected signal name")
	}
}

func TestSuggestionsProbe(t *testing.T) {
	probe := BuildSuggestionsProbe("user")
	ok, sig := Analyze(`{"data":{}}`, `{"errors":[{"message":"Cannot query field \"user_nonexistent_field_xyz\" on type \"Query\". Did you mean \"users\"?"}]}`, probe)
	if !ok || sig != "field_suggestions_exposed" {
		t.Fatal("expected field suggestions zafiyeti tespiti")
	}
}

func TestGraphQLFieldAuthLeakRejectsErrorResponseFP(t *testing.T) {
	probe := BuildAuthorizationBypassProbes("user")[3] // field-level auth probe

	// Error response mentioning apiKey and password in validation message (Must be rejected as FP)
	errorResponses := []string{
		`{"errors":[{"message":"Cannot query field \"apiKey\" on type \"User\"."}]}`,
		`{"errors":[{"message":"Field \"password\" of type \"String\" is not valid for User."}]}`,
		`{"errors":[{"message":"Validation error of type FieldUndefined: Field 'secretToken' in type 'User' is undefined"}]}`,
		`{"data":null,"errors":[{"message":"Field apiKey is not defined on type User"}]}`,
		`{"data":{"user":null},"errors":[{"message":"Field password cannot be queried"}]}`,
	}

	baseline := `{"data":{"user":{"id":1,"name":"Alice"}}}`

	for i, errResp := range errorResponses {
		ok, sig := Analyze(baseline, errResp, probe)
		if ok || sig != "" {
			t.Fatalf("error response #%d was incorrectly flagged as leak (FP): ok=%v sig=%s body=%s", i, ok, sig, errResp)
		}
	}
}

func TestGraphQLFieldAuthLeakAcceptsRealDataLeak(t *testing.T) {
	probe := BuildAuthorizationBypassProbes("user")[3] // field-level auth probe

	// Genuine leak returning data inside 'data' tree
	realLeakResponse := `{"data":{"user":{"id":1,"email":"alice@test.com","apiKey":"sk_live_secret_99887766"}}}`
	baseline := `{"data":{"user":{"id":1,"name":"Alice"}}}`

	ok, sig := Analyze(baseline, realLeakResponse, probe)
	if !ok || sig != "graphql_field_auth_leak" {
		t.Fatalf("expected genuine data leak to be confirmed: ok=%v sig=%s", ok, sig)
	}
}
