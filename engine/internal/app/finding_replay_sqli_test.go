package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/verification"
)

func TestStoredSQLiComparisonCannotBeReconfirmedByHTTPBodyReplay(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/sqli-replay.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	const scanID = "sqli-replay"
	if err := db.EnsureScan(scanID); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultScanConfig()
	cfg.Targets = []string{"https://example.test/"}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateScanConfig(scanID, string(raw)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		class  string
		proof  verification.ProofType
		reason string
	}{
		{"sqli", verification.ProofBooleanPair, "paired SQLi verifier"},
		{"sqli", verification.ProofArithmeticOracle, "paired SQLi verifier"},
		{"route_auth_bypass", verification.ProofDifferentialReplay, "private-resource access"},
	} {
		evidence, err := json.Marshal(map[string]interface{}{
			"request":      map[string]string{"method": "GET", "url": "https://example.test/search?id=1"},
			"verification": map[string]string{"proof_type": string(tc.proof)},
		})
		if err != nil {
			t.Fatal(err)
		}
		id, err := db.SaveFinding(scanID, tc.class, "high", tc.class, "legacy comparison proof", "https://example.test/search", "id", .9, string(evidence))
		if err != nil {
			t.Fatal(err)
		}
		result, err := (&Engine{db: db}).ReplayFinding(context.Background(), id)
		if err != nil || result.Status != "inconclusive" || !strings.Contains(result.Reason, tc.reason) {
			t.Fatalf("old %s comparison proof was reconfirmed through HTTP replay: %+v err=%v", tc.class, result, err)
		}
	}
}
