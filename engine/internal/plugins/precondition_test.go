package plugins

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/models"
)

func TestPluginPreconditionsSkipReasons(t *testing.T) {
	intel := models.EndpointIntelligence{
		URL:             "https://example.com/static/app.js",
		Method:          "GET",
		EndpointType:    "script",
		ContentType:     "application/javascript",
		AuthRequired:    false,
		StateChanging:   false,
		TechFingerprint: &models.TechFingerprint{Hints: []string{"framework:WordPress"}},
	}

	ready, skipped := EvaluatePreconditions(intel)
	if len(ready) > 0 {
		t.Fatalf("expected all modules skipped, ready=%v", ready)
	}
	if len(skipped) == 0 {
		t.Fatal("expected skip reasons")
	}
	foundGraphQL := false
	for _, s := range skipped {
		if s.Module == "graphql" {
			foundGraphQL = true
			if s.Reason == "" {
				t.Fatal("skip reason should not be empty")
			}
		}
	}
	if !foundGraphQL {
		t.Fatal("graphql module should be skipped with reason")
	}
}

func TestGraphQLModuleReady(t *testing.T) {
	intel := models.EndpointIntelligence{
		URL:           "https://example.com/graphql",
		Method:        "POST",
		EndpointType:  "graphql",
		ContentType:   "application/json",
		AuthRequired:  true,
		StateChanging: true,
	}
	ready, skipped := EvaluatePreconditions(intel)
	hasGraphQL := false
	for _, m := range ready {
		if m == "graphql" {
			hasGraphQL = true
		}
	}
	if !hasGraphQL {
		t.Fatalf("graphql should be ready, ready=%v skipped=%v", ready, skipped)
	}
}
