package app

import (
	"github.com/akha-security/akca/engine/internal/config"
	"testing"
)

func TestModuleReadinessDoesNotClaimUnconfiguredProof(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.AllowedVulnerabilityClasses = []string{"idor"}
	checks := moduleReadiness(cfg)
	if len(checks) != 1 || checks[0].Module != "idor" || checks[0].Configured {
		t.Fatalf("incorrect readiness: %+v", checks)
	}
}
