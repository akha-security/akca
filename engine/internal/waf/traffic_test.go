package waf

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/models"
)

func TestRecommendTrafficBudgetForDetectedWAF(t *testing.T) {
	p := models.WAFProfile{Vendor: "Cloudflare", CautiousModeRecommended: true}
	b := RecommendTrafficBudget(p, 50, 30, 48, 16)
	if b.GlobalRateLimit != 50 || b.PerHostRateLimit != 30 ||
		b.MaxConcurrency != 48 || b.PerHostConcurrency != 16 || b.Adjusted ||
		b.Reason != "passive_waf_observed" {
		t.Fatalf("unexpected WAF traffic budget: %+v", b)
	}
}

func TestRecommendTrafficBudgetForActiveChallenge(t *testing.T) {
	p := models.WAFProfile{Vendor: "Cloudflare", CautiousModeRecommended: true, RateLimitDetected: true}
	b := RecommendTrafficBudget(p, 50, 30, 48, 16)
	if b.GlobalRateLimit != 3 || b.PerHostRateLimit != 2 ||
		b.MaxConcurrency != 4 || b.PerHostConcurrency != 2 || !b.Adjusted {
		t.Fatalf("unexpected active challenge budget: %+v", b)
	}
}

func TestRecommendTrafficBudgetNeverRaisesOperatorLimits(t *testing.T) {
	p := models.WAFProfile{Vendor: "Akamai", CautiousModeRecommended: true}
	b := RecommendTrafficBudget(p, 0.5, 0.25, 2, 1)
	if b.GlobalRateLimit != 0.5 || b.PerHostRateLimit != 0.25 ||
		b.MaxConcurrency != 2 || b.PerHostConcurrency != 1 || b.Adjusted {
		t.Fatalf("operator's lower limits must be preserved: %+v", b)
	}
}
