package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/logincapture"
	"github.com/akha-security/akca/engine/internal/scope"
)

func (e *Engine) handleLoginQuery(input CommandInput, params map[string]interface{}, emit func(interface{}) error) error {
	switch input.Query {
	case "start_login_capture":
		return e.startLoginCapture(params, emit)
	case "poll_login_session":
		return e.pollLoginSession(params, emit)
	case "stop_login_capture":
		return e.stopLoginCapture(params, emit)
	case "automated_login":
		return e.automatedLogin(params, emit)
	case "apply_login_session":
		return e.applyLoginSession(params, emit)
	default:
		return fmt.Errorf("unknown login query: %s", input.Query)
	}
}

func (e *Engine) ensureLoginCaptureManager() *logincapture.Manager {
	if e.platform == nil {
		e.initPlatform(platformDataDir())
	}
	if e.platform.loginCapture == nil {
		e.platform.loginCapture = logincapture.NewManager()
	}
	return e.platform.loginCapture
}

func (e *Engine) startLoginCapture(params map[string]interface{}, emit func(interface{}) error) error {
	loginURL := strings.TrimSpace(strParam(params, "login_url"))
	if loginURL == "" {
		return fmt.Errorf("login_url is required")
	}
	sessionID := strParam(params, "session_id")
	if sessionID == "" {
		sessionID = fmt.Sprintf("login-%d", time.Now().UnixNano())
	}

	u, err := url.Parse(loginURL)
	if err != nil {
		return err
	}
	host := u.Hostname()
	scopeCfg := config.DefaultScanConfig()
	scopeCfg.Targets = []string{loginURL}
	scopeCfg.IncludeDomains = []string{host}
	scopeEngine := scope.NewEngine(scopeCfg)

	mgr := e.ensureLoginCaptureManager()
	srv := logincapture.NewCaptureServer(e.db, scopeEngine, sessionID)
	if boolParam(params, "record_workflow") {
		workflowID := strParam(params, "workflow_id")
		if workflowID == "" {
			workflowID = "workflow-" + sessionID
		}
		workflowName := strParam(params, "workflow_name")
		if workflowName == "" {
			workflowName = "Captured login workflow"
		}
		srv.EnableWorkflowRecording(workflowID, workflowName, strParam(params, "identity"))
	}
	addr, err := srv.Start("127.0.0.1:0")
	if err != nil {
		return err
	}
	mgr.Register(sessionID, srv)
	return emit(map[string]interface{}{
		"session_id":         sessionID,
		"proxy_url":          "http://" + addr,
		"login_url":          loginURL,
		"force_http1":        true,
		"workflow_recording": boolParam(params, "record_workflow"),
	})
}

func (e *Engine) pollLoginSession(params map[string]interface{}, emit func(interface{}) error) error {
	sessionID := strParam(params, "session_id")
	mgr := e.ensureLoginCaptureManager()
	srv, ok := mgr.Get(sessionID)
	if !ok {
		return fmt.Errorf("login capture session not found: %s", sessionID)
	}
	sess := srv.Session()
	return emit(map[string]interface{}{
		"session_id":     sessionID,
		"cookies":        sess.Cookies,
		"headers":        sess.Headers,
		"captured_count": len(sess.Cookies),
		"workflow":       sess.Workflow,
	})
}

func (e *Engine) stopLoginCapture(params map[string]interface{}, emit func(interface{}) error) error {
	sessionID := strParam(params, "session_id")
	mgr := e.ensureLoginCaptureManager()
	sess, ok := mgr.Stop(sessionID)
	if !ok {
		return fmt.Errorf("login capture session not found: %s", sessionID)
	}
	return emit(map[string]interface{}{
		"session_id": sessionID,
		"cookies":    sess.Cookies,
		"headers":    sess.Headers,
		"notes":      sess.Notes,
		"workflow":   sess.Workflow,
	})
}

func (e *Engine) automatedLogin(params map[string]interface{}, emit func(interface{}) error) error {
	req := logincapture.LoginRequest{
		LoginURL:      strParam(params, "login_url"),
		Username:      strParam(params, "username"),
		Password:      strParam(params, "password"),
		UsernameField: strParam(params, "username_field"),
		PasswordField: strParam(params, "password_field"),
		ForceHTTP1:    true,
	}
	if req.Username == "" {
		req.Username = strParam(params, "email")
	}
	if boolParam(params, "allow_http2") {
		req.ForceHTTP1 = false
	}
	if raw, ok := params["extra_fields"].(map[string]interface{}); ok {
		req.ExtraFields = parseStringMap(raw)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	sess, err := logincapture.AutomatedLogin(ctx, req)
	if err != nil {
		return err
	}
	return emit(map[string]interface{}{
		"cookies": sess.Cookies,
		"headers": sess.Headers,
		"notes":   sess.Notes,
	})
}

func (e *Engine) applyLoginSession(params map[string]interface{}, emit func(interface{}) error) error {
	cookies := parseStringMap(params["cookies"])
	headers := parseStringMap(params["headers"])
	profileID := strParam(params, "profile_id")
	profileName := strParam(params, "profile_name")

	e.mu.Lock()
	cfg := e.session.Config
	if len(cookies) > 0 {
		if cfg.SessionCookies == nil {
			cfg.SessionCookies = map[string]string{}
		}
		for k, v := range cookies {
			cfg.SessionCookies[k] = v
		}
	}
	if len(headers) > 0 {
		if cfg.CustomHeaders == nil {
			cfg.CustomHeaders = map[string]string{}
		}
		for k, v := range headers {
			cfg.CustomHeaders[k] = v
		}
	}
	if profileID != "" {
		updated := false
		for i, p := range cfg.AuthProfiles {
			if p.ID == profileID {
				if p.Cookies == nil {
					p.Cookies = map[string]string{}
				}
				for k, v := range cookies {
					p.Cookies[k] = v
				}
				for k, v := range headers {
					if p.Headers == nil {
						p.Headers = map[string]string{}
					}
					p.Headers[k] = v
				}
				cfg.AuthProfiles[i] = p
				updated = true
				break
			}
		}
		if !updated {
			name := profileName
			if name == "" {
				name = "Captured Session"
			}
			cfg.AuthProfiles = append(cfg.AuthProfiles, config.AuthProfile{
				ID:      profileID,
				Name:    name,
				Cookies: cookies,
				Headers: headers,
			})
		}
	}
	cfg.ForceHTTP1 = true
	e.session.Config = cfg
	if e.client != nil {
		e.applyAuth(cfg)
	}
	e.mu.Unlock()
	return emit(map[string]interface{}{
		"applied":         true,
		"cookie_count":    len(cookies),
		"header_count":    len(headers),
		"force_http1":     true,
		"session_cookies": cfg.SessionCookies,
		"custom_headers":  cfg.CustomHeaders,
		"auth_profiles":   cfg.AuthProfiles,
	})
}

func parseStringMap(raw interface{}) map[string]string {
	out := map[string]string{}
	switch v := raw.(type) {
	case map[string]string:
		return v
	case map[string]interface{}:
		for k, val := range v {
			out[k] = fmt.Sprintf("%v", val)
		}
	}
	return out
}

func (e *Engine) resolveLoginSession(cfg *config.ScanConfig) error {
	return e.resolveLoginSessionContext(context.Background(), cfg)
}

func (e *Engine) resolveLoginSessionContext(parent context.Context, cfg *config.ScanConfig) error {
	if cfg.LoginCredentials == nil {
		return nil
	}
	lc := cfg.LoginCredentials
	if strings.TrimSpace(lc.LoginURL) == "" {
		return nil
	}
	user := lc.Username
	if user == "" {
		user = lc.Email
	}
	if user == "" || lc.Password == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(parent, 60*time.Second)
	defer cancel()
	sess, err := logincapture.AutomatedLogin(ctx, logincapture.LoginRequest{
		LoginURL:      lc.LoginURL,
		Username:      user,
		Password:      lc.Password,
		UsernameField: lc.UsernameField,
		PasswordField: lc.PasswordField,
		ForceHTTP1:    cfg.ForceHTTP1,
	})
	if err != nil {
		return fmt.Errorf("automated login: %w", err)
	}
	if cfg.SessionCookies == nil {
		cfg.SessionCookies = map[string]string{}
	}
	for k, v := range sess.Cookies {
		cfg.SessionCookies[k] = v
	}
	for k, v := range sess.Headers {
		if cfg.CustomHeaders == nil {
			cfg.CustomHeaders = map[string]string{}
		}
		cfg.CustomHeaders[k] = v
	}
	if len(cfg.AuthProfiles) > 0 {
		if cfg.AuthProfiles[0].Cookies == nil {
			cfg.AuthProfiles[0].Cookies = map[string]string{}
		}
		for k, v := range sess.Cookies {
			cfg.AuthProfiles[0].Cookies[k] = v
		}
	}
	_ = e.Emit("log", "automated login captured session cookies", map[string]interface{}{
		"cookie_count": len(sess.Cookies),
	})
	return nil
}

// ensureAuthenticatedSession validates the active login immediately before
// authenticated discovery or attack traffic. If the session expired, it
// performs one fresh login and verifies the new session. A failed verification
// is returned to the pipeline so it can stop before anonymous responses are
// interpreted as vulnerability evidence.
func (e *Engine) ensureAuthenticatedSession(ctx context.Context) error {
	cfg := e.session.Snapshot().Config
	if !loginSessionGuardEnabled(cfg) {
		return nil
	}

	healthy, detail, err := e.checkSessionHeartbeat(ctx, cfg)
	if err == nil && healthy {
		_ = e.Emit("session_heartbeat_ok", "authenticated session is healthy", map[string]interface{}{
			"url": sessionHeartbeatURL(cfg),
		})
		return nil
	}
	_ = e.Emit("session_expired", "authenticated session heartbeat failed", map[string]interface{}{
		"url":    sessionHeartbeatURL(cfg),
		"detail": detail,
	})
	if cfg.LoginCredentials.DisableAutoRelogin {
		if err != nil {
			return fmt.Errorf("session heartbeat failed and automatic re-login is disabled: %w", err)
		}
		return fmt.Errorf("session heartbeat failed and automatic re-login is disabled: %s", detail)
	}

	if err := e.resolveLoginSessionContext(ctx, &cfg); err != nil {
		return fmt.Errorf("session re-authentication failed: %w", err)
	}
	e.mu.Lock()
	e.session.UpdateConfig(cfg)
	e.applyAuth(cfg)
	e.mu.Unlock()

	healthy, detail, err = e.checkSessionHeartbeat(ctx, cfg)
	if err != nil {
		return fmt.Errorf("refreshed session heartbeat failed: %w", err)
	}
	if !healthy {
		return fmt.Errorf("refreshed session could not be verified: %s", detail)
	}
	_ = e.Emit("session_reauthenticated", "expired session was refreshed and verified", map[string]interface{}{
		"url": sessionHeartbeatURL(cfg),
	})
	return nil
}

func loginSessionGuardEnabled(cfg config.ScanConfig) bool {
	lc := cfg.LoginCredentials
	if lc == nil || strings.TrimSpace(lc.LoginURL) == "" || strings.TrimSpace(lc.Password) == "" {
		return false
	}
	return strings.TrimSpace(lc.Username) != "" || strings.TrimSpace(lc.Email) != ""
}

func sessionHeartbeatURL(cfg config.ScanConfig) string {
	if cfg.LoginCredentials == nil {
		return ""
	}
	if heartbeat := strings.TrimSpace(cfg.LoginCredentials.HeartbeatURL); heartbeat != "" {
		return heartbeat
	}
	// Authenticated applications commonly redirect their login endpoint to the
	// application; an expired session returns the password form recognized
	// below. This provides a safe automatic default without extra configuration.
	return strings.TrimSpace(cfg.LoginCredentials.LoginURL)
}

func (e *Engine) checkSessionHeartbeat(ctx context.Context, cfg config.ScanConfig) (bool, string, error) {
	rr, err := e.client.Do(ctx, http.MethodGet, sessionHeartbeatURL(cfg), nil, map[string]string{
		"Cache-Control": "no-cache",
		"Pragma":        "no-cache",
	})
	if err != nil {
		return false, "heartbeat request error", err
	}
	return sessionHeartbeatHealthy(
		rr.Response.StatusCode,
		rr.Response.Headers,
		rr.Response.Body,
		cfg.LoginCredentials,
	)
}

func sessionHeartbeatHealthy(status int, headers map[string]string, body string, lc *config.LoginCredentials) (bool, string, error) {
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return false, fmt.Sprintf("HTTP %d indicates an unauthenticated session", status), nil
	}
	if status < 200 || status >= 400 {
		return false, fmt.Sprintf("unexpected heartbeat status HTTP %d", status), nil
	}

	location := ""
	for key, value := range headers {
		if strings.EqualFold(key, "Location") {
			location = strings.ToLower(value)
			break
		}
	}
	if strings.Contains(location, "login") || strings.Contains(location, "signin") || strings.Contains(location, "sign-in") {
		return false, "heartbeat redirected to a login endpoint", nil
	}

	lowerBody := strings.ToLower(body)
	if lc != nil {
		if marker := strings.TrimSpace(lc.LoggedOutMarker); marker != "" &&
			strings.Contains(lowerBody, strings.ToLower(marker)) {
			return false, "configured logged-out marker was present", nil
		}
		if marker := strings.TrimSpace(lc.LoggedInMarker); marker != "" {
			if !strings.Contains(lowerBody, strings.ToLower(marker)) {
				return false, "configured logged-in marker was absent", nil
			}
			return true, "configured logged-in marker was present", nil
		}
	}
	if strings.Contains(lowerBody, `type="password"`) || strings.Contains(lowerBody, `type='password'`) {
		return false, "heartbeat returned a password form", nil
	}
	return true, "heartbeat response remained authenticated", nil
}

// mergeLoginSessionFromJSON applies cookies/headers from a JSON blob (used by tests).
func mergeLoginSessionFromJSON(cfg *config.ScanConfig, raw json.RawMessage) {
	var sess logincapture.Session
	if json.Unmarshal(raw, &sess) != nil {
		return
	}
	if cfg.SessionCookies == nil {
		cfg.SessionCookies = map[string]string{}
	}
	for k, v := range sess.Cookies {
		cfg.SessionCookies[k] = v
	}
}
