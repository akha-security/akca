package app

import (
	"context"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/fingerprint"
	"github.com/akha-security/akca/engine/internal/models"
	"github.com/akha-security/akca/engine/internal/plugins"
	"github.com/akha-security/akca/engine/internal/waf"
)

const fingerprintHTTPTimeout = 20 * time.Second

func (e *Engine) httpStep(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, fingerprintHTTPTimeout)
}

func (e *Engine) runFingerprintPhase(ctx context.Context, target string) error {
	e.session.SetPhase("fingerprinting")
	_ = e.Emit("phase_started", "fingerprinting", map[string]interface{}{"phase": "fingerprinting", "target": target})
	_ = e.Emit("scan_progress", "fingerprinting target", map[string]interface{}{
		"scan_id": e.session.ID, "phase": "fingerprinting", "target": target,
	})

	metrics := eventsMetricAggregator(e, e.session.ID)

	var wafProfile models.WAFProfile
	if e.session.Config.EnableWAFDetection {
		wafProfiler := waf.NewProfiler(e.client)
		stepCtx, cancel := e.httpStep(ctx)
		profile, err := wafProfiler.Profile(stepCtx, target)
		cancel()
		if err != nil {
			_ = e.Emit("log", "waf profile skipped: "+err.Error(), map[string]interface{}{"target": target})
		} else {
			wafProfile = profile
			var trafficBudget *waf.TrafficBudget
			if wafProfile.CautiousModeRecommended {
				current := e.session.Snapshot().Config
				budget := waf.RecommendTrafficBudget(wafProfile,
					current.GlobalRateLimit, current.PerHostRateLimit,
					current.MaxConcurrency, current.PerHostConcurrency)
				if budget.Adjusted && e.limiter != nil {
					waf.ApplyCautiousMode(e.limiter, wafProfile, current.GlobalRateLimit, budget.GlobalRateLimit)
				}
				trafficBudget = &budget
			}
			_ = e.db.SaveWAFProfile(e.session.ID, wafProfile)
			_ = e.Emit("waf_detected", wafProfile.Vendor, map[string]interface{}{
				"host":                      wafProfile.Host,
				"vendor":                    wafProfile.Vendor,
				"cdn":                       wafProfile.CDN,
				"cautious_mode_recommended": wafProfile.CautiousModeRecommended,
				"confidence":                wafProfile.Confidence,
			})
			if trafficBudget != nil {
				_ = e.Emit("waf_traffic_adjusted", trafficBudget.Reason, map[string]interface{}{
					"host": wafProfile.Host, "vendor": wafProfile.Vendor,
					"global_rate_limit":    trafficBudget.GlobalRateLimit,
					"per_host_rate_limit":  trafficBudget.PerHostRateLimit,
					"max_concurrency":      trafficBudget.MaxConcurrency,
					"per_host_concurrency": trafficBudget.PerHostConcurrency,
					"adjusted":             trafficBudget.Adjusted,
				})
			}
			_ = metrics.Inc("waf_detected", 1)
		}
	}

	var techFP models.TechFingerprint
	if e.session.Config.EnableJSAnalysis || e.session.Config.EnableWAFDetection {
		techProfiler := fingerprint.NewTechFingerprinter(e.client)
		stepCtx, cancel := e.httpStep(ctx)
		fp, fpErr := techProfiler.Fingerprint(stepCtx, target)
		cancel()
		if fpErr != nil {
			_ = e.Emit("log", "tech fingerprint skipped: "+fpErr.Error(), map[string]interface{}{"target": target})
		} else {
			techFP = fp
			_ = e.db.SaveTechFingerprint(e.session.ID, techFP)
			_ = e.Emit("tech_fingerprint_complete", techFP.Framework, map[string]interface{}{
				"host":             techFP.Host,
				"backend_language": techFP.BackendLanguage,
				"framework":        techFP.Framework,
				"database":         techFP.Database,
				"server_cdn":       techFP.ServerCDN,
				"js_framework":     techFP.JSFramework,
				"hints":            techFP.Hints,
				"components":       techFP.Components,
				"page_title":       techFP.PageTitle,
			})
			_ = metrics.Inc("tech_fingerprint_complete", 1)
		}
	}

	stepCtx, cancel := e.httpStep(ctx)
	rr, rrErr := e.client.Do(stepCtx, "GET", target, nil, nil)
	cancel()
	contentType := ""
	body := ""
	if rrErr == nil {
		body = rr.Response.Body
		for k, v := range rr.Response.Headers {
			if strings.EqualFold(k, "Content-Type") {
				contentType = v
				break
			}
		}
	}

	var wafPtr *models.WAFProfile
	if wafProfile.Host != "" {
		wafPtr = &wafProfile
	}
	var techPtr *models.TechFingerprint
	if techFP.Host != "" {
		techPtr = &techFP
	}

	intel := fingerprint.ClassifyEndpoint(target, "GET", contentType, body, wafPtr, techPtr)
	_, _ = e.db.SaveEndpointIntelligence(e.session.ID, target, "GET", intel)

	ready, skipped := plugins.EvaluatePreconditions(intel)
	for _, reason := range skipped {
		_ = e.Emit("plugin_skipped", reason.Reason, map[string]interface{}{
			"module":   reason.Module,
			"endpoint": reason.Endpoint,
			"reason":   reason.Reason,
		})
		_ = metrics.Inc("plugin_skipped", 1)
	}
	_ = metrics.Inc("plugins_ready", len(ready))
	_ = metrics.Flush()

	_ = e.Emit("phase_finished", "fingerprinting", map[string]interface{}{
		"phase":           "fingerprinting",
		"ready_modules":   ready,
		"skipped_modules": len(skipped),
	})
	return nil
}

func eventsMetricAggregator(e *Engine, scanID string) *metricBridge {
	return newMetricBridge(scanID, e.Emit)
}
