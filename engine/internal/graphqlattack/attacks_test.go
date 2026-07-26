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
