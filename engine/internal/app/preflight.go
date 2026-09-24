package app

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/akha-security/akca/engine/internal/config"
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
