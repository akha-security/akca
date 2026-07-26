package planner_test

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/learning"
	"github.com/akha-security/akca/engine/internal/planner"
)

func TestRequestOrderingWithLearning(t *testing.T) {
	domain := learning.NewProfile("example.com", "")
	domain = domain.Record("api", learning.OutcomeWorked)
	domain = domain.Record("admin", learning.OutcomeFalsePositive)
	p := planner.New(map[string]learning.Profile{"example.com": domain})
	items := []planner.RequestItem{
		{URL: "https://example.com/admin", Parameter: "admin", Priority: 50},
		{URL: "https://example.com/api/users", Parameter: "api", Priority: 50},
	}
	ordered := p.Order(items)
	if ordered[0].URL != "https://example.com/api/users" {
		t.Fatalf("expected api endpoint first, got %+v", ordered)
	}
}
