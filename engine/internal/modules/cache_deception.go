package modules

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/verification"
)

var wcdEmailRe = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)

func (r *Runner) runCacheDeception(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("cache_deception", target); !ok {
		r.emitSkip("cache_deception", target, reason)
		return nil
	}
	// Web Cache Deception is an endpoint-level path confusion attack, not a parameter-level injection.
	target.Parameter = ""

	// Skip unexpanded route template paths like /confirm-email/{token}
	if strings.ContainsAny(target.EndpointURL, "{}") {
		return nil
	}

	anonymous, ok := r.client.(sessionlessHTTPDoer)
	if !ok {
		return nil
	}
	parsed, err := url.Parse(target.EndpointURL)
	if err != nil {
		return nil
	}
	basePath := strings.TrimSuffix(parsed.Path, "/")
	privateURL := parsed.Scheme + "://" + parsed.Host + basePath
	privateBaseline, err := r.client.Do(ctx, http.MethodGet, privateURL, nil, nil)
	if err != nil || privateBaseline.Response.StatusCode >= 400 {
		return nil
	}

	canary := ""
	if policy, ok := r.cacheDeceptionPolicy(target); ok && policy.PrivateCanary != "" {
		canary = policy.PrivateCanary
	} else {
		// Heuristic detection: must find structured private identifiers (e.g. an actual email address)
		// rather than static generic words like "email" or "token" which appear on public pages.
		m := wcdEmailRe.FindString(privateBaseline.Response.Body)
		if m != "" && !strings.HasSuffix(m, ".png") && !strings.HasSuffix(m, ".jpg") {
			canary = m
		}
		// In heuristic mode, verify that this canary is truly private by checking
		// that an unauthenticated (anonymous) request to privateURL does NOT see it.
		if canary != "" {
			anonBase, anonErr := anonymous.DoWithoutSession(ctx, http.MethodGet, privateURL, nil, nil)
			if anonErr == nil && anonBase.Response.StatusCode < 400 {
				if strings.Contains(anonBase.Response.Body, canary) || anonBase.Response.Body == privateBaseline.Response.Body {
					// Canary is public, not private data!
					canary = ""
				}
			}
		}
	}
	if canary == "" || !strings.Contains(privateBaseline.Response.Body, canary) {
		r.emitSkip("cache_deception", target, "a private canary or authenticated profile data is required")
		return nil
	}

	coldURL := privateURL + "/akca-cold-" + randomToken(10) + ".css"
	cold, err := anonymous.DoWithoutSession(ctx, http.MethodGet, coldURL, nil, nil)
	if err != nil || strings.Contains(cold.Response.Body, canary) {
		return nil
	}
	probes := []struct{ path, signal string }{
		{basePath + "/nonexistent.css", "path_confusion_css"},
		{basePath + "/test.js", "path_confusion_js"},
		{basePath + "/avatar.ico", "path_confusion_ico"},
		{basePath + "/data.json", "path_confusion_json"},
		{basePath + "/font.woff2", "path_confusion_woff2"},
		{basePath + "/image.svg", "path_confusion_svg"},
		{basePath + "/..%2fprofile.css", "path_confusion_traversal"},
		{basePath + ";.css", "path_confusion_semicolon"},
		{basePath + "%3B.css", "path_confusion_encoded_semicolon"},
		{basePath + "%0A.css", "path_confusion_newline"},
		{basePath + "%23.css", "path_confusion_hash"},
		{basePath + "%3F.css", "path_confusion_encoded_question"},
		{basePath + "/.test.css", "path_confusion_dotfile"},
		{basePath + "?cb=akca.css", "path_confusion_query_cache_key"},
	}
	for _, probe := range probes {
		rawURL := parsed.Scheme + "://" + parsed.Host + probe.path
		prime, primeErr := r.client.Do(ctx, http.MethodGet, rawURL, nil, nil)
		if primeErr != nil || prime.Response.StatusCode >= 400 || !strings.Contains(prime.Response.Body, canary) {
			continue
		}
		var victims []httpclient.RequestResponse
		for attempt := 0; attempt < 3; attempt++ {
			victim, victimErr := anonymous.DoWithoutSession(ctx, http.MethodGet, rawURL, nil, nil)
			if victimErr != nil || victim.Response.StatusCode >= 400 || !strings.Contains(victim.Response.Body, canary) ||
				!cacheEvidence(victim.Response.Headers) {
				victims = nil
				break
			}
			victims = append(victims, victim)
		}
		if len(victims) != 3 {
			continue
		}
		payload := defaultPayload("cache_deception", probe.signal, probe.path, "private_canary_anonymous_cache_hit")
		finding := r.verifyAndBuildWithCandidate(ctx, "cache_deception", target, payload, cold, victims[0],
			"private_canary_anonymous_cache_hit", false, false, "", "", func(candidate *verification.Candidate) {
				candidate.RequestedProofType = verification.ProofDifferentialReplay
				candidate.NegativeControlSet, candidate.NegativeControlOK = true, true
				candidate.TypedReplayHits = []bool{true, true, true}
				candidate.Observations = append(candidate.Observations,
					r.observation("cache_deception", target, verification.RoleBaselineReplay, 1, privateBaseline),
					r.observation("cache_deception", target, verification.RolePositiveReplay, 2, victims[1]),
					r.observation("cache_deception", target, verification.RolePositiveReplay, 3, victims[2]),
					r.observation("cache_deception", target, verification.RoleNegativeControl, 1, cold),
				)
			})
		if finding != nil {
			finding.Title = "Web Cache Deception via " + probe.signal
			finding.Severity = "high"
			finding.Description = "An authenticated private response was primed through a deceptive static extension path and retrieved repeatedly without a session from cache."
			var out []ModuleFinding
			r.recordFinding(ctx, &out, finding, "cache_deception", "private_canary_anonymous_cache_hit")
			return out
		}
	}
	return nil
}

func (r *Runner) cacheDeceptionPolicy(target ScanTarget) (config.CacheDeceptionProofPolicy, bool) {
	for _, policy := range r.cfg.CacheDeceptionProofPolicies {
		if strings.Contains(target.EndpointURL, policy.URLContains) {
			return policy, true
		}
	}
	return config.CacheDeceptionProofPolicy{}, false
}

func cacheDeceptionSignal(body, baseline string, headers map[string]string) bool {
	return body != baseline && cacheEvidence(headers)
}
