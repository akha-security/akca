package modules

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/verification"
)

func (r *Runner) runCacheDeception(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("cache_deception", target); !ok {
		r.emitSkip("cache_deception", target, reason)
		return nil
	}
	policy, ok := r.cacheDeceptionPolicy(target)
	if !ok {
		r.emitSkip("cache_deception", target, "a user-seeded private canary policy is required")
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
	if err != nil || !strings.Contains(privateBaseline.Response.Body, policy.PrivateCanary) {
		return nil
	}
	coldURL := privateURL + "/akca-cold-" + randomToken(10) + ".css"
	cold, err := anonymous.DoWithoutSession(ctx, http.MethodGet, coldURL, nil, nil)
	if err != nil || strings.Contains(cold.Response.Body, policy.PrivateCanary) {
		return nil
	}
	probes := []struct{ path, signal string }{
		{basePath + "/nonexistent.css", "path_confusion_css"},
		{basePath + "/..%2fprofile", "path_confusion_traversal"},
		{basePath + ";.css", "path_confusion_semicolon"},
	}
	for _, probe := range probes {
		rawURL := parsed.Scheme + "://" + parsed.Host + probe.path
		prime, primeErr := r.client.Do(ctx, http.MethodGet, rawURL, nil, nil)
		if primeErr != nil || !strings.Contains(prime.Response.Body, policy.PrivateCanary) {
			continue
		}
		var victims []httpclient.RequestResponse
		for attempt := 0; attempt < 3; attempt++ {
			victim, victimErr := anonymous.DoWithoutSession(ctx, http.MethodGet, rawURL, nil, nil)
			if victimErr != nil || !strings.Contains(victim.Response.Body, policy.PrivateCanary) ||
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
			finding.Description = "An authenticated private canary was primed through a deceptive path and retrieved three times without a session from cache; a cold-cache control did not expose it."
			var out []ModuleFinding
			r.recordFinding(&out, finding, "cache_deception", "private_canary_anonymous_cache_hit")
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
