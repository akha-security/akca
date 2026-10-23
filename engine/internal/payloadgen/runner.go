package payloadgen

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/learning"
	"github.com/akha-security/akca/engine/internal/reflection"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/wafintel"
)

type Generator struct {
	scanID string
	db     *storage.DB
	cfg    config.ScanConfig
	emit   EventSink
}

func NewGenerator(scanID string, db *storage.DB, cfg config.ScanConfig, emit EventSink) *Generator {
	return &Generator{scanID: scanID, db: db, cfg: cfg, emit: emit}
}

func (g *Generator) Run(ctx context.Context, profiles []reflection.ReflectionProfile) ([]GenerationResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := g.emit("payload_generation_started", "payload generation started", map[string]interface{}{"scan_id": g.scanID}); err != nil {
		return nil, fmt.Errorf("failed to emit payload generation start event: %w", err)
	}
	budget := g.cfg.PayloadBudgetLimit()
	store := learning.NewStore(g.db)

	var results []GenerationResult
	for _, profile := range profiles {
		profile.ScanID = g.scanID
		if err := ctx.Err(); err != nil {
			return results, err
		}
		host := hostFromURL(profile.EndpointURL)
		tech, err := g.db.GetTechFingerprint(g.scanID, host)
		if err != nil && err != sql.ErrNoRows {
			return nil, fmt.Errorf("database query failure for tech fingerprint on host %s: %w", host, err)
		}
		waf, err := g.db.GetWAFProfile(g.scanID, host)
		if err != nil && err != sql.ErrNoRows {
			return nil, fmt.Errorf("database query failure for WAF profile on host %s: %w", host, err)
		}
		wafLearning := g.wafLearningProfile(host)
		learnData := store.Load(host, profile.EndpointURL)
		w, b, n, fp := learnData.ToPayloadGen()

		targetBudget := budget

		result := Generate(Input{
			Profile: profile,
			Tech: TechHints{
				BackendLanguage: tech.BackendLanguage,
				Framework:       tech.Framework,
				Database:        tech.Database,
				ServerCDN:       tech.ServerCDN,
				JSFramework:     tech.JSFramework,
				Hints:           append([]string(nil), tech.Hints...),
			},
			WAF:    WAFHintsForProfile(g.cfg, waf, wafLearning),
			Budget: targetBudget,
			Learn: LearningProfile{
				Worked: w, Blocked: b, Noisy: n, FalsePositive: fp,
			},
		})
		results = append(results, result)
		if err := g.db.SaveGeneratedPayloadsContext(ctx, g.scanID, profile.EndpointURL, profile.Parameter, result); err != nil {
			return nil, fmt.Errorf("failed to save generated payloads for %s (param: %s): %w", profile.EndpointURL, profile.Parameter, err)
		}
		if err := store.Save(learnData); err != nil {
			return nil, fmt.Errorf("failed to save learning store data for host %s: %w", host, err)
		}
		if err := g.emit("payloads_generated", profile.Parameter, map[string]interface{}{
			"scan_id": g.scanID, "endpoint": profile.EndpointURL, "parameter": profile.Parameter,
			"count": len(result.Payloads), "skipped": result.Skipped, "budget_used": result.BudgetUsed,
		}); err != nil {
			return nil, fmt.Errorf("failed to emit payloads generated event for parameter %s: %w", profile.Parameter, err)
		}
		if result.Shadow.SQLiTestCases > 0 {
			if err := g.emit("payload_planner_shadow_comparison", profile.Parameter, map[string]interface{}{
				"scan_id": g.scanID, "endpoint": profile.EndpointURL, "parameter": profile.Parameter,
				"legacy_payloads":      result.Shadow.LegacyPayloads,
				"test_cases":           result.Shadow.TestCases,
				"legacy_budget":        result.Shadow.LegacyBudget,
				"estimated_requests":   result.Shadow.EstimatedRequests,
				"sqli_legacy_payloads": result.Shadow.SQLiLegacyPayloads,
				"sqli_test_cases":      result.Shadow.SQLiTestCases,
				"orphan_controls":      result.Shadow.OrphanControls,
			}); err != nil {
				return nil, fmt.Errorf("failed to emit payload planner shadow comparison for parameter %s: %w", profile.Parameter, err)
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return results, err
	}
	if err := g.emit("payload_generation_finished", "payload generation finished", map[string]interface{}{
		"scan_id": g.scanID, "endpoints": len(results),
	}); err != nil {
		return nil, fmt.Errorf("failed to emit payload generation finished event: %w", err)
	}
	return results, ctx.Err()
}

func (g *Generator) wafLearningProfile(host string) wafintel.LearningProfile {
	learn := wafintel.NewLearningProfile(host)
	if g.db == nil || strings.TrimSpace(host) == "" {
		return learn
	}
	raw, err := g.db.LoadWAFLearningProfile(host)
	if err != nil {
		return learn
	}
	if json.Unmarshal([]byte(raw), &learn) != nil {
		return wafintel.NewLearningProfile(host)
	}
	return learn
}

func hostFromURL(raw string) string {
	return wafintel.HostFromTarget(raw)
}
