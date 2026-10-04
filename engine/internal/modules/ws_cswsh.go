package modules

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/verification"
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
		if f == nil && r.hasCookieAuthentication() {
			var replays []httpclient.RequestResponse
			for i := 0; i < 2; i++ {
				replay, replayErr := r.client.Do(ctx, "GET", target.EndpointURL, nil, wsHeaders)
				if replayErr != nil || replay.Response.StatusCode != 101 {
					replays = nil
					break
				}
				replays = append(replays, replay)
			}
			if len(replays) == 2 {
				p := defaultPayload("ws_cswsh", "cross_origin_upgrade_with_cookie", wsHeaders["Origin"], "cross_origin_upgrade_with_cookie")
				finding := r.verifyAndBuildWithCandidate(ctx, "ws_cswsh", target, p, baseline, rr,
					"cross_origin_upgrade_with_cookie", false, false, "", "", func(candidate *verification.Candidate) {
						candidate.RequestedProofType = verification.ProofConfiguration
						candidate.Observations = append(candidate.Observations,
							r.observation("ws_cswsh", target, verification.RolePositiveReplay, 2, replays[0]),
							r.observation("ws_cswsh", target, verification.RolePositiveReplay, 3, replays[1]))
					})
				if finding != nil {
					finding.Severity = "medium"
					finding.Title = "WebSocket accepts an untrusted Origin with ambient cookies"
					finding.Description = "The WebSocket handshake repeatedly accepted an attacker Origin while the scan used cookie-based authentication. This proves a missing Origin check; private message disclosure was not inferred."
					r.recordFinding(ctx, &out, finding, "ws_cswsh", "cross_origin_upgrade_with_cookie")
				}
			}
		}

	}

	return out
}

func (r *Runner) hasCookieAuthentication() bool {
	if len(r.cfg.SessionCookies) > 0 {
		return true
	}
	for _, profile := range r.cfg.AuthProfiles {
		if len(profile.Cookies) > 0 {
			return true
		}
	}
	return false
}
