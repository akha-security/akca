package modules

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

func (r *Runner) runCrossSiteWebSocketHijack(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("ws_cswsh", target); !ok {
		r.emitSkip("ws_cswsh", target, reason)
		return nil
	}

	u, err := url.Parse(target.EndpointURL)
	if err != nil {
		return nil
	}

	// Only test endpoints that support WebSocket or look like ws endpoints
	lowerPath := strings.ToLower(u.Path)
	if !strings.Contains(lowerPath, "ws") && !strings.Contains(lowerPath, "socket") &&
		!strings.Contains(lowerPath, "chat") && !strings.Contains(lowerPath, "stream") &&
		!strings.Contains(lowerPath, "realtime") {
		return nil
	}

	baseline, baselineErr := r.cachedEmptyProbe(ctx, target)
	if baselineErr != nil {
		return nil
	}

	var out []ModuleFinding

	// Test cross-site origin in WebSocket handshake
	wsHeaders := map[string]string{
		"Upgrade":               "websocket",
		"Connection":            "Upgrade",
		"Sec-WebSocket-Key":     "dGhlIHNhbXBsZSBub25jZQ==",
		"Sec-WebSocket-Version": "13",
		"Origin":                "https://attacker-evil-origin.example.com",
	}

	rr, err := r.client.Do(ctx, "GET", target.EndpointURL, nil, wsHeaders)
	if err == nil && rr.Response.StatusCode == 101 {
		// Server accepted the WebSocket upgrade from a malicious cross-site Origin!
		signal := "cswsh_cross_origin_accepted"
		p := defaultPayload("ws_cswsh", signal, "Origin: https://attacker-evil-origin.example.com", signal)
		f := r.verifyAndBuild(ctx, "ws_cswsh", target, p, baseline, rr, signal, false, false, "", "")
		if f != nil {
			hasAuth := len(r.cfg.SessionCookies) > 0 || len(r.cfg.Authentication) > 0 || len(r.cfg.CustomHeaders) > 0 || len(target.RequestTemplate.Headers) > 0
			if hasAuth {
				f.Severity = "high"
				f.Title = "Cross-Site WebSocket Hijacking (CSWSH) with Ambient Credentials"
				f.Description = fmt.Sprintf("WebSocket endpoint '%s' accepted cross-origin upgrade handshake (Status: 101 Switching Protocols) using authenticated session cookies from an untrusted Origin.", target.EndpointURL)
			} else {
				f.Severity = "info"
				f.Title = "Cross-Site WebSocket Hijacking (CSWSH) - Public Service Allowed"
				f.Description = fmt.Sprintf("WebSocket endpoint '%s' accepted cross-origin upgrade handshake (Status: 101 Switching Protocols) without origin validation. No ambient credentials were configured on this probe.", target.EndpointURL)
			}
			r.recordFinding(ctx, &out, f, "ws_cswsh", signal)
		}
	}

	return out
}
