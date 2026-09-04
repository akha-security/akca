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
	if authenticated && (status == http.StatusUnauthorized || status == http.StatusForbidden) {
		return fmt.Errorf("authentication preflight returned HTTP %d; configured credentials were not accepted", status)
	}
	return nil
}
