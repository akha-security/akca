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

		r.emitDiscovery("ws_cswsh", target, "cross_origin_upgrade", "Cross-origin upgrade accepted; handshake alone does not prove private data access")
		f := r.proveCrossOriginRead(ctx, "ws_cswsh", target, "websocket", "", baseline, rr)
		if f != nil {
			f.Severity = "high"
			f.Title = "Cross-Site WebSocket Private Data Disclosure"
			f.Description = fmt.Sprintf("Browser script at an opaque origin read the configured private canary from %s in two authenticated sessions; an anonymous browser control did not expose it.", target.EndpointURL)
			r.recordFinding(ctx, &out, f, "ws_cswsh", "browser_private_read")
		}

	}

	return out
}
