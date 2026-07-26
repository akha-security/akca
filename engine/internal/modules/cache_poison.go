package modules

import (
	"context"
	"net/url"
	"strconv"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/verification"
)

func (r *Runner) runCachePoisoning(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("cache_poisoning", target); !ok {
		r.emitSkip("cache_poisoning", target, reason)
		return nil
	}
	anonymous, ok := r.client.(sessionlessHTTPDoer)
	if !ok {
		r.emitSkip("cache_poisoning", target, "anonymous victim session is unavailable")
		return nil
	}
	var out []ModuleFinding
	probes := []struct {
		headers map[string]string
		signal  string
	}{
		{map[string]string{}, "unkeyed_header_host"},
		{map[string]string{}, "unkeyed_original_url"},
		{map[string]string{}, "unkeyed_custom_header"},
	}
	for index, pr := range probes {
		marker := "akca-cache-" + randomToken(10) + ".invalid"
		switch index {
		case 0:
			pr.headers["X-Forwarded-Host"] = marker
		case 1:
			pr.headers["X-Original-URL"] = "/" + marker
		default:
			pr.headers["X-Akca-Poison"] = marker
		}
		cacheURL := cacheCanaryURL(target.EndpointURL, randomToken(12))
		baseline, err := anonymous.DoWithoutSession(ctx, "GET", cacheURL, nil, nil)
		if err != nil || strings.Contains(baseline.Response.Body, marker) {
			continue
		}
		rr, err := r.client.Do(ctx, "GET", cacheURL, nil, pr.headers)
		if err != nil {
			continue
		}
		if !cachePoisonCandidate(baseline.Response.Body, rr.Response.Body, marker) {
			continue
		}
		var victims []httpclient.RequestResponse
		for replay := 0; replay < 3; replay++ {
			victim, victimErr := anonymous.DoWithoutSession(ctx, "GET", cacheURL, nil, nil)
			if victimErr != nil || !cachePoisonPersisted(baseline.Response.Body, victim.Response.Body, victim.Response.Headers, marker) {
				victims = nil
				break
			}
			victims = append(victims, victim)
		}
		if len(victims) != 3 {
			continue
		}
		cold, err := anonymous.DoWithoutSession(ctx, "GET",
			cacheCanaryURL(target.EndpointURL, randomToken(12)), nil, nil)
		if err != nil || strings.Contains(cold.Response.Body, marker) {
			continue
		}
		p := defaultPayload("cache_poisoning", pr.signal, marker, pr.signal)
		f := r.verifyAndBuildWithCandidate(ctx, "cache_poisoning", target, p, baseline, victims[0],
			pr.signal, false, false, "", "", func(candidate *verification.Candidate) {
				candidate.RequestedProofType = verification.ProofDifferentialReplay
				candidate.NegativeControlSet = true
				candidate.NegativeControlOK = true
				candidate.TypedReplayHits = []bool{true, true, true}
				candidate.Observations = append(candidate.Observations,
					r.observation("cache_poisoning", target, verification.RolePositiveReplay, 2, victims[1]),
					r.observation("cache_poisoning", target, verification.RolePositiveReplay, 3, victims[2]),
					r.observation("cache_poisoning", target, verification.RoleNegativeControl, 1, cold),
				)
			})
		r.recordFinding(&out, f, "cache_poisoning", pr.signal)
	}
	return out
}

func cacheCanaryURL(rawURL, token string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	query := parsed.Query()
	query.Set("_akca_cache", token)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func cachePoisonCandidate(baseline, body, marker string) bool {
	return !strings.Contains(baseline, marker) && strings.Contains(body, marker)
}

func cachePoisonPersisted(baseline, body string, headers map[string]string, marker string) bool {
	return cachePoisonCandidate(baseline, body, marker) && cacheEvidence(headers)
}

func cacheEvidence(headers map[string]string) bool {
	for _, name := range []string{"X-Cache", "CF-Cache-Status", "X-Proxy-Cache"} {
		value := strings.ToLower(headerValue(headers, name))
		if strings.Contains(value, "hit") || strings.Contains(value, "cached") {
			return true
		}
	}
	age, err := strconv.Atoi(strings.TrimSpace(headerValue(headers, "Age")))
	if err == nil && age > 0 {
		return true
	}
	return false
}
