package app

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/browserpool"
	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/oast"
)

// runPreflightValidation prevents a scan from spending its budget on an
// unusable gateway or silently scanning the logged-out surface.
func (e *Engine) runPreflightValidation(ctx context.Context, cfg config.ScanConfig) error {
	for _, readiness := range moduleReadiness(cfg) {
		_ = e.Emit("module_readiness", readiness.Reason, map[string]interface{}{"module": readiness.Module, "configured": readiness.Configured, "reason": readiness.Reason})
		if !readiness.Configured {
			_ = e.Emit("log", readiness.Module+": "+readiness.Reason, map[string]interface{}{"phase": "preflight", "module": readiness.Module})
		}
	}
	if len(cfg.Targets) == 0 {
		return fmt.Errorf("preflight requires at least one target")
	}
	if cfg.EnableOAST {
		listener := e.OAST()
		if listener == nil {
			_ = e.Emit("coverage_gap", "OAST is enabled but no listener is available; blind vulnerability coverage is disabled", map[string]interface{}{
				"phase": "preflight", "capability": "oast", "affected_modules": []string{"blind_xss", "ssrf", "xxe", "sqli", "ssti", "command_injection", "insecure_deserialization", "pdf_injection", "server_side_js_injection", "llm_injection"},
			})
		} else if err := listener.HealthCheck(ctx, 5*time.Second); err != nil {
			_ = e.Emit("coverage_gap", "OAST registration succeeded but the end-to-end callback self-test failed", map[string]interface{}{
				"phase": "preflight", "capability": "oast", "reason": err.Error(), "blind_coverage": false,
			})
			_ = e.Emit("oast_failed", "OAST callback path is unavailable; blind probes were disabled for this scan", map[string]interface{}{
				"phase": "preflight", "capability": "oast", "reason": err.Error(), "blind_coverage": false,
			})
			e.disableUnhealthyOAST(listener)
		} else {
			_ = e.Emit("capability_ready", "OAST end-to-end callback path verified", map[string]interface{}{"phase": "preflight", "capability": "oast"})
		}
	}
	// Capability readiness is emitted after the end-to-end OAST check so a
	// successful registration with a broken callback path is never advertised
	// as ready.
	e.emitCapabilityMatrix(cfg)
	if loginSessionGuardEnabled(cfg) {
		if err := e.ensureAuthenticatedSession(ctx); err != nil {
			return fmt.Errorf("authentication preflight failed: %w", err)
		}
	}
	rr, err := e.client.Do(ctx, http.MethodGet, cfg.Targets[0], nil, map[string]string{"Cache-Control": "no-cache", "Pragma": "no-cache"})
	if err != nil {
		return fmt.Errorf("target preflight failed: %w", err)
	}
	if err := preflightStatusError(rr.Response.StatusCode, scanHasConfiguredAuth(cfg)); err != nil {
		return err
	}
	_ = e.Emit("preflight_ok", "target and authentication preflight passed", map[string]interface{}{"target": cfg.Targets[0], "status": rr.Response.StatusCode, "authenticated": scanHasConfiguredAuth(cfg)})
	return nil
}

func (e *Engine) disableUnhealthyOAST(listener *oast.Listener) {
	e.mu.Lock()
	if e.oast == listener {
		e.oast = nil
		if e.session != nil {
			e.session.Config.EnableOAST = false
		}
	}
	e.mu.Unlock()
	listener.Stop()
}

func (e *Engine) emitCapabilityMatrix(cfg config.ScanConfig) {
	type capability struct {
		ready   bool
		reason  string
		modules []string
	}
	browserAvailable := false
	if cfg.EnableHeadlessCrawler || cfg.EnableBrowserWorkerPool {
		browserAvailable = browserpool.NewHeadlessRendererWithProxy(cfg.ProxyURL, cfg.InsecureSkipVerify).Available()
	}
	workflowConfigured := len(cfg.RaceProofPolicies)+len(cfg.BusinessLogicProofPolicies)+
		len(cfg.AccountRecoveryProofPolicies)+len(cfg.WebhookProofPolicies)+len(cfg.CSRFProofPolicies)+
		len(cfg.SessionLifecycleProofPolicies)+len(cfg.FileUploadProofPolicies)+
		len(cfg.CacheDeceptionProofPolicies)+len(cfg.HPPProofPolicies) > 0
	runtimeSensorReady := e.platform != nil && e.platform.sensor != nil
	matrix := map[string]capability{
		"browser":              {browserAvailable, "no usable Chromium-compatible browser is available", []string{"xss", "csti_detection", "client_ssti", "jsonp_callback", "ws_cswsh"}},
		"oast":                 {cfg.EnableOAST && e.oast != nil, "OAST listener is disabled or unavailable", []string{"blind_xss", "ssrf", "xxe", "sqli", "ssti", "command_injection"}},
		"two_roles":            {len(cfg.RoleProfiles) >= 2, "at least two distinct role profiles are required", []string{"idor", "tenant_isolation", "bfla"}},
		"ownership_policy":     {len(cfg.ObjectAuthorizationPolicies) > 0, "object ownership policy is missing", []string{"idor", "tenant_isolation"}},
		"authorization_policy": {len(cfg.AuthorizationPolicies) > 0, "function authorization policy is missing", []string{"bfla"}},
		"workflow_policy":      {workflowConfigured, "no stateful workflow proof policy is configured", []string{"business_logic", "race_condition", "account_recovery", "webhook_security", "csrf", "session_lifecycle", "file_upload", "cache_deception", "hpp"}},
		"runtime_sensor":       {runtimeSensorReady, "runtime sensor is unavailable; sink-level confirmation is disabled", []string{"sqli", "ssti", "command_injection", "ssrf", "xxe", "insecure_deserialization", "react_rsc_rce"}},
	}
	payload := make(map[string]interface{}, len(matrix))
	for name, item := range matrix {
		payload[name] = map[string]interface{}{"ready": item.ready, "reason": item.reason, "affected_modules": item.modules}
		if !item.ready {
			_ = e.Emit("capability_gap", item.reason, map[string]interface{}{"phase": "preflight", "capability": name, "affected_modules": item.modules})
		}
	}
	_ = e.Emit("capability_matrix", "scanner capability readiness evaluated", payload)
}

type readinessEntry struct {
	Module     string
	Configured bool
	Reason     string
}

// Configuration readiness is not a claim that every endpoint has a matching policy.
func moduleReadiness(cfg config.ScanConfig) []readinessEntry {
	rateConfigured := false
	for _, p := range cfg.RateLimitPolicies {
		if p.WindowSeconds > 0 {
			rateConfigured = true
		}
	}
	checks := []readinessEntry{
		{"idor", len(cfg.RoleProfiles) >= 2 && len(cfg.ObjectAuthorizationPolicies) > 0, "two role profiles and object ownership policies required"},
		{"tenant_isolation", len(cfg.RoleProfiles) >= 2 && len(cfg.ObjectAuthorizationPolicies) > 0, "two role profiles and object ownership policies required"},
		{"bfla", len(cfg.AuthorizationPolicies) > 0, "authorization, state and cleanup policies required"},
		{"race_condition", len(cfg.RaceProofPolicies) > 0, "recorded transaction, state and cleanup policy required"},
		{"business_logic", len(cfg.BusinessLogicProofPolicies) > 0, "recorded invariant, state and cleanup policy required"},
		{"account_recovery", len(cfg.AccountRecoveryProofPolicies) > 0, "recorded recovery and state policy required"},
		{"webhook_security", len(cfg.WebhookProofPolicies) > 0, "recorded unsigned-event and state policy required"},
		{"rate_limit", rateConfigured, "an account, threshold and window_seconds policy is required for vulnerability proof"},
	}
	out := []readinessEntry{}
	for _, check := range checks {
		if !cfg.AllowsModule(check.Module) {
			continue
		}
		if check.Configured {
			check.Reason = "configuration present; endpoint policy matching and proof still required"
		}
		out = append(out, check)
	}
	return out
}

func scanHasConfiguredAuth(cfg config.ScanConfig) bool {
	if loginSessionGuardEnabled(cfg) || len(cfg.Authentication) > 0 || len(cfg.SessionCookies) > 0 || len(cfg.AuthProfiles) > 0 {
		return true
	}
	for name, value := range cfg.CustomHeaders {
		if strings.EqualFold(name, "Authorization") && strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

func preflightStatusError(status int, authenticated bool) error {
	if status == http.StatusBadGateway {
		return fmt.Errorf("target preflight returned HTTP 502 Bad Gateway; scan aborted before consuming the request budget")
	}
	if status == http.StatusServiceUnavailable {
		return fmt.Errorf("target preflight returned HTTP 503 Service Unavailable; target may be under maintenance")
	}
	if status == http.StatusGatewayTimeout {
		return fmt.Errorf("target preflight returned HTTP 504 Gateway Timeout; upstream is unresponsive")
	}
	if status >= 500 {
		return fmt.Errorf("target preflight returned HTTP %d; scan aborted due to server-side error", status)
	}
	if authenticated && (status == http.StatusUnauthorized || status == http.StatusForbidden) {
		return fmt.Errorf("authentication preflight returned HTTP %d; configured credentials were not accepted", status)
	}
	return nil
}
