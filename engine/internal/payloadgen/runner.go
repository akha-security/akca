package payloadgen

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/learning"
	"github.com/akha-security/akca/engine/internal/reflection"
	"github.com/akha-security/akca/engine/internal/storage"
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
	if err := g.emit("payload_generation_started", "payload generation started", map[string]interface{}{"scan_id": g.scanID}); err != nil {
		return nil, fmt.Errorf("failed to emit payload generation start event: %w", err)
	}
	budget := g.cfg.PayloadBudgetLimit()
	store := learning.NewStore(g.db)

	var results []GenerationResult
	for _, profile := range profiles {
		host := hostFromURL(profile.EndpointURL)
		tech, err := g.db.GetTechFingerprint(g.scanID, host)
		if err != nil && err != sql.ErrNoRows {
			return nil, fmt.Errorf("database query failure for tech fingerprint on host %s: %w", host, err)
		}
		waf, err := g.db.GetWAFProfile(g.scanID, host)
		if err != nil && err != sql.ErrNoRows {
			return nil, fmt.Errorf("database query failure for WAF profile on host %s: %w", host, err)
		}
		learnData := store.Load(host, profile.EndpointURL)
		w, b, n, fp := learnData.ToPayloadGen()

		// Start cautiously behind a WAF. A positive signal can trigger deeper
		// verification later; sending the full library up front increases bans.
		targetBudget := budget
		if waf.CautiousModeRecommended || waf.Vendor != "" {
			targetBudget = lowerPositiveBudget(targetBudget, 6)
		} else {
			targetBudget = lowerPositiveBudget(targetBudget, 15)
		}

		result := Generate(Input{
			Profile: profile,
			Tech: TechHints{
				BackendLanguage: tech.BackendLanguage,
				Framework:       tech.Framework,
				Database:        tech.Database,
			},
			WAF: WAFHints{
				Vendor:                  waf.Vendor,
				CautiousModeRecommended: waf.CautiousModeRecommended,
				AllowEvasion:            g.cfg.EnableWAFBypassHeaders,
			},
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
	}
	if err := g.emit("payload_generation_finished", "payload generation finished", map[string]interface{}{
		"scan_id": g.scanID, "endpoints": len(results),
	}); err != nil {
		return nil, fmt.Errorf("failed to emit payload generation finished event: %w", err)
	}
	return results, nil
}

func lowerPositiveBudget(configured, ceiling int) int {
	if configured <= 0 || configured > ceiling {
		return ceiling
	}
	return configured
}

func hostFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
