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
		headerKey string
		headerVal func(marker string) string
		signal    string
	}{
		{"X-Forwarded-Host", func(m string) string { return m }, "unkeyed_forwarded_host"},
		{"X-Host", func(m string) string { return m }, "unkeyed_host"},
		{"X-Forwarded-Server", func(m string) string { return m }, "unkeyed_forwarded_server"},
		{"X-HTTP-Host-Override", func(m string) string { return m }, "unkeyed_host_override"},
		{"X-Original-URL", func(m string) string { return "/" + m }, "unkeyed_original_url"},
		{"X-Rewrite-URL", func(m string) string { return "/" + m }, "unkeyed_rewrite_url"},
		{"X-Forwarded-Proto", func(m string) string { return "http" }, "unkeyed_forwarded_proto"},
		{"X-Forwarded-Scheme", func(m string) string { return "nothttps" }, "unkeyed_forwarded_scheme"},
		{"X-Custom-IP-Authorization", func(m string) string { return m }, "unkeyed_custom_ip"},
		{"X-Akca-Poison", func(m string) string { return m }, "unkeyed_custom_header"},
	}
	for _, pr := range probes {
		marker := "akca-cache-" + randomToken(10) + ".invalid"
		headers := map[string]string{pr.headerKey: pr.headerVal(marker)}
		cacheURL := cacheCanaryURL(target.EndpointURL, randomToken(12))
		baseline, err := anonymous.DoWithoutSession(ctx, "GET", cacheURL, nil, nil)
		if err != nil || strings.Contains(baseline.Response.Body, marker) {
			continue
		}
		rr, err := r.client.Do(ctx, "GET", cacheURL, nil, headers)
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
		if f != nil {
			f.Title = "Web Cache Poisoning via " + pr.headerKey
			f.Severity = "high"
			f.Description = "An unkeyed HTTP header was reflected into the response and persisted in intermediate cache layers for anonymous clients."
			r.recordFinding(ctx, &out, f, "cache_poisoning", pr.signal)
		}
		if len(out) >= 3 {
			break
		}
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
	return cachePoisonCandidate(baseline, body, marker) && !isUncacheableResponse(headers) && cacheEvidence(headers)
}

func cacheEvidence(headers map[string]string) bool {
	for _, name := range []string{
		"X-Cache", "CF-Cache-Status", "X-Proxy-Cache", "Fastly-Cache-Status",
		"X-Cache-Hits", "X-Varnish", "X-Drupal-Cache", "X-Rack-Cache", "X-Cache-Lookup",
	} {
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
